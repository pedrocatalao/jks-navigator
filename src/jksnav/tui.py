from __future__ import annotations

import argparse
import curses
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.utils import CryptographyDeprecationWarning

from .crypto import format_fingerprint_sha256, load_x509_der
from .jks import JKSStore, PrivateKeyEntry, TrustedCertEntry


@dataclass
class AppState:
    keystore_path: str | None = None
    storepass: str | None = None
    store: JKSStore | None = None
    selected: int = 0
    alias_scroll: int = 0
    detail_scroll: int = 0
    focus: str = "list"
    filter_text: str = ""
    status: str = "Press 'o' to open a keystore. 'q' quits."
    error: bool = False


def _prompt(stdscr: curses.window, label: str, secret: bool = False, initial: str = "") -> str | None:
    h, w = stdscr.getmaxyx()
    width = min(max(56, len(label) + 8), max(20, w - 4))
    win = curses.newwin(5, width, max(0, h // 2 - 2), max(0, (w - width) // 2))
    win.keypad(True)
    curses.curs_set(1)
    text = list(initial)

    while True:
        win.erase()
        win.box()
        win.addnstr(1, 2, label, width - 4)
        shown = ("*" * len(text)) if secret else "".join(text)
        win.addnstr(2, 2, shown, width - 4)
        win.move(2, min(width - 3, 2 + len(shown)))
        win.refresh()
        ch = win.getch()
        if ch in (10, 13):
            curses.curs_set(0)
            return "".join(text)
        if ch in (27,):
            curses.curs_set(0)
            return None
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if text:
                text.pop()
            continue
        if ch == curses.KEY_RESIZE:
            h, w = stdscr.getmaxyx()
            width = min(max(56, len(label) + 8), max(20, w - 4))
            win.resize(5, width)
            win.mvwin(max(0, h // 2 - 2), max(0, (w - width) // 2))
            continue
        if 32 <= ch <= 126:
            text.append(chr(ch))


def _picker_entries(current: Path) -> list[tuple[str, Path, bool]]:
    entries: list[tuple[str, Path, bool]] = []
    parent = current.parent if current.parent != current else current
    entries.append(("../", parent, True))
    try:
        children = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError:
        return entries
    for child in children:
        if child.is_dir():
            entries.append((f"{child.name}/", child, True))
        elif child.suffix.lower() == ".jks":
            entries.append((child.name, child, False))
    return entries


def _pick_jks_file(stdscr: curses.window, start_dir: Path | None = None) -> str | None:
    current = (start_dir or Path.cwd()).expanduser().resolve()
    if not current.is_dir():
        current = current.parent if current.parent.exists() else Path.cwd()
    selected = 0
    scroll = 0

    while True:
        h, w = stdscr.getmaxyx()
        if h < 10 or w < 40:
            stdscr.erase()
            stdscr.addnstr(0, 0, "Window too small for file picker. Resize, then press any key.", max(0, w - 1))
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (27, ord("q"), ord("Q")):
                return None
            continue
        modal_h = min(max(16, h - 6), h - 2)
        modal_w = min(max(72, w - 8), w - 2)
        top = max(0, (h - modal_h) // 2)
        left = max(0, (w - modal_w) // 2)
        win = curses.newwin(modal_h, modal_w, top, left)
        win.keypad(True)

        entries = _picker_entries(current)
        if entries:
            selected = max(0, min(selected, len(entries) - 1))
        else:
            selected = 0
        rows = modal_h - 6
        if selected < scroll:
            scroll = selected
        if selected >= scroll + rows:
            scroll = selected - rows + 1
        scroll = max(0, scroll)

        win.erase()
        win.box()
        win.addnstr(0, 2, " Open Keystore ", max(0, modal_w - 4))
        win.addnstr(1, 2, str(current), max(0, modal_w - 4))
        win.addnstr(2, 2, "Choose a folder or .jks file", max(0, modal_w - 4))

        for i in range(rows):
            idx = scroll + i
            if idx >= len(entries):
                break
            label, _, _ = entries[idx]
            row = 4 + i
            if idx == selected:
                win.attron(curses.color_pair(3))
                win.addnstr(row, 2, label.ljust(modal_w - 4), max(0, modal_w - 5))
                win.attroff(curses.color_pair(3))
            else:
                win.addnstr(row, 2, label, max(0, modal_w - 5))

        help_line = "Enter open/select | Backspace/h parent | Esc cancel"
        win.addnstr(modal_h - 2, 2, help_line, max(0, modal_w - 4))
        win.refresh()

        ch = win.getch()
        if ch in (27, ord("q"), ord("Q")):
            return None
        if ch in (curses.KEY_UP, ord("k")) and entries:
            selected = max(0, selected - 1)
            continue
        if ch in (curses.KEY_DOWN, ord("j")) and entries:
            selected = min(len(entries) - 1, selected + 1)
            continue
        if ch == curses.KEY_PPAGE and entries:
            selected = max(0, selected - rows)
            continue
        if ch == curses.KEY_NPAGE and entries:
            selected = min(len(entries) - 1, selected + rows)
            continue
        if ch in (curses.KEY_BACKSPACE, 127, 8, ord("h")):
            current = current.parent if current.parent != current else current
            selected = 0
            scroll = 0
            continue
        if 32 <= ch <= 126:
            key = chr(ch).lower()
            if key.isalnum() and entries:
                # Prefer real files over directories for type-to-jump.
                file_match = next(
                    (
                        i
                        for i, (label, _, is_dir) in enumerate(entries)
                        if not is_dir and label.lower().startswith(key)
                    ),
                    None,
                )
                any_match = next(
                    (i for i, (label, _, _) in enumerate(entries) if label.lower().startswith(key)),
                    None,
                )
                match = file_match if file_match is not None else any_match
                if match is not None:
                    selected = match
            continue
        if ch in (10, 13):
            if not entries:
                continue
            _, target, is_dir = entries[selected]
            if is_dir:
                current = target
                selected = 0
                scroll = 0
                continue
            return str(target)


def _visible_aliases(state: AppState) -> list[str]:
    if state.store is None:
        return []
    aliases = state.store.aliases()
    if not state.filter_text:
        return aliases
    needle = state.filter_text.lower()
    return [a for a in aliases if needle in a.lower()]


def _load_keystore(state: AppState, path: str, storepass: str) -> None:
    p = str(Path(path).expanduser())
    store = JKSStore.load(p, storepass)
    state.keystore_path = p
    state.storepass = storepass
    state.store = store
    state.selected = 0
    state.alias_scroll = 0
    state.detail_scroll = 0
    state.status = f"Loaded {p}"
    state.error = False


def _cert_lines(alias: str, entry: PrivateKeyEntry | TrustedCertEntry) -> tuple[list[str], bool]:
    lines: list[str] = []
    lines.append(f"Alias: {alias}")
    lines.append(f"Entry type: {'PrivateKeyEntry' if isinstance(entry, PrivateKeyEntry) else 'trustedCertEntry'}")
    lines.append(f"Created: {entry.timestamp.astimezone().isoformat(sep=' ', timespec='seconds')}")
    lines.append("")

    cert_der = None
    if isinstance(entry, PrivateKeyEntry):
        lines.append(f"Chain length: {len(entry.chain)}")
        if entry.chain:
            cert_der = entry.chain[0].cert_data
    else:
        cert_der = entry.cert.cert_data

    if cert_der is None:
        lines.append("No certificate data available.")
        return lines, False

    cert = load_x509_der(cert_der)
    expired = cert.not_valid_after_utc < datetime.now(timezone.utc)
    serial_warning = False
    dn_warning = False
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            owner_text = cert.subject.rfc4514_string()
        except Exception:
            owner_text = "<unavailable>"
        try:
            issuer_text = cert.issuer.rfc4514_string()
        except Exception:
            issuer_text = "<unavailable>"
        try:
            serial_text = f"{cert.serial_number:x}"
        except Exception:
            serial_text = "<unavailable>"
        serial_warning = any(issubclass(w.category, CryptographyDeprecationWarning) for w in caught)
        dn_warning = any("Attribute's length must be >= 1 and <= 64" in str(w.message) for w in caught)

    lines.extend(
        [
            f"Owner: {owner_text}",
            f"Issuer: {issuer_text}",
            f"Serial: {serial_text}",
            f"Valid from: {cert.not_valid_before_utc.isoformat(sep=' ', timespec='seconds')}",
            f"Valid to:   {cert.not_valid_after_utc.isoformat(sep=' ', timespec='seconds')}",
            f"SHA-256: {format_fingerprint_sha256(cert)}",
            f"Signature algorithm: {cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string}",
        ]
    )
    if dn_warning:
        lines.extend(
            [
                "",
                "Warning: Certificate subject/issuer has attributes with invalid length.",
                "Some tooling may treat these distinguished names as non-compliant.",
            ]
        )
    if serial_warning:
        lines.extend(
            [
                "",
                "Warning: Certificate serial number is non-positive.",
                "Future cryptography versions may reject this certificate.",
            ]
        )
    return lines, expired


def _draw(stdscr: curses.window, state: AppState) -> None:
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if h < 14 or w < 70:
        stdscr.addstr(0, 0, "Window too small. Resize to at least 70x14.")
        stdscr.refresh()
        return

    list_width = max(26, w // 3)
    split_x = list_width

    title = " jks-navigator TUI "
    location = state.keystore_path or "<no keystore loaded>"
    header = f"{title} | {location}"
    stdscr.attron(curses.color_pair(1))
    stdscr.addnstr(0, 0, header.ljust(w), w)
    stdscr.attroff(curses.color_pair(1))

    aliases = _visible_aliases(state)
    if aliases:
        state.selected = max(0, min(state.selected, len(aliases) - 1))
    else:
        state.selected = 0
    list_rows = h - 4
    if state.selected < state.alias_scroll:
        state.alias_scroll = state.selected
    if state.selected >= state.alias_scroll + list_rows:
        state.alias_scroll = state.selected - list_rows + 1
    state.alias_scroll = max(0, state.alias_scroll)

    stdscr.addnstr(1, 1, f"Aliases ({len(aliases)})", split_x - 2)
    filter_label = f"Filter: {state.filter_text or '<none>'}"
    stdscr.addnstr(2, 1, filter_label, split_x - 2)

    for i in range(list_rows):
        row = 3 + i
        idx = state.alias_scroll + i
        if idx >= len(aliases):
            break
        alias = aliases[idx]
        if idx == state.selected and state.focus == "list":
            stdscr.attron(curses.color_pair(3))
            stdscr.addnstr(row, 1, alias.ljust(split_x - 2), split_x - 2)
            stdscr.attroff(curses.color_pair(3))
        elif idx == state.selected:
            stdscr.attron(curses.A_BOLD)
            stdscr.addnstr(row, 1, alias.ljust(split_x - 2), split_x - 2)
            stdscr.attroff(curses.A_BOLD)
        else:
            stdscr.addnstr(row, 1, alias, split_x - 2)

    for y in range(1, h - 1):
        stdscr.addch(y, split_x, curses.ACS_VLINE)

    detail_x = split_x + 2
    detail_w = w - detail_x - 1
    stdscr.addnstr(1, detail_x, f"Details ({'active' if state.focus == 'details' else 'idle'})", detail_w)

    detail_lines: list[str] = ["No alias selected."]
    expired = False
    if aliases and state.store is not None:
        entry = state.store.get(aliases[state.selected])
        if entry is not None:
            detail_lines, expired = _cert_lines(aliases[state.selected], entry)
    detail_rows = h - 4
    max_scroll = max(0, len(detail_lines) - detail_rows)
    state.detail_scroll = max(0, min(state.detail_scroll, max_scroll))

    for i in range(detail_rows):
        idx = state.detail_scroll + i
        if idx >= len(detail_lines):
            break
        text = detail_lines[idx]
        if expired and text.startswith("Valid to:"):
            stdscr.attron(curses.color_pair(4))
            stdscr.addnstr(3 + i, detail_x, text, detail_w)
            stdscr.attroff(curses.color_pair(4))
        else:
            stdscr.addnstr(3 + i, detail_x, text, detail_w)

    help_line = "Tab switch pane | Up/Down navigate | PgUp/PgDn scroll | / filter | c clear | o open | r reload | q quit"
    stdscr.attron(curses.color_pair(2))
    stdscr.addnstr(h - 2, 0, help_line.ljust(w), w)
    stdscr.attroff(curses.color_pair(2))

    status_color = 5 if state.error else 2
    stdscr.attron(curses.color_pair(status_color))
    # Avoid writing the bottom-right corner cell; curses may raise ERR there.
    stdscr.addnstr(h - 1, 0, f" {state.status}".ljust(w), max(0, w - 1))
    stdscr.attroff(curses.color_pair(status_color))
    stdscr.refresh()


def _open_flow(stdscr: curses.window, state: AppState) -> None:
    existing = state.keystore_path or str(Path.cwd())
    path = _pick_jks_file(stdscr, Path(existing))
    if path is None or not path.strip():
        state.status = "Open cancelled."
        state.error = False
        return
    default_pass = state.storepass or ""
    pw = _prompt(stdscr, "Store password (Esc cancels):", secret=True, initial=default_pass)
    if pw is None:
        state.status = "Open cancelled."
        state.error = False
        return
    try:
        _load_keystore(state, path.strip(), pw)
    except Exception as exc:
        state.status = f"Failed to load keystore: {exc}"
        state.error = True


def _run(stdscr: curses.window, initial_path: str | None, initial_storepass: str | None) -> int:
    curses.use_default_colors()
    curses.curs_set(0)
    stdscr.keypad(True)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_RED)

    state = AppState()
    if initial_path is not None:
        try:
            _load_keystore(state, initial_path, initial_storepass or "")
        except Exception as exc:
            state.status = f"Startup load failed: {exc}"
            state.error = True
    else:
        selected = _pick_jks_file(stdscr, Path.cwd())
        if selected is None:
            state.status = "No keystore selected. Press 'o' to open."
            state.error = False
        else:
            pw = _prompt(stdscr, "Store password (Esc cancels):", secret=True, initial=initial_storepass or "")
            if pw is None:
                state.status = "Open cancelled. Press 'o' to open."
                state.error = False
            else:
                try:
                    _load_keystore(state, selected, pw)
                except Exception as exc:
                    state.status = f"Startup load failed: {exc}"
                    state.error = True

    while True:
        _draw(stdscr, state)
        ch = stdscr.getch()
        aliases = _visible_aliases(state)

        if ch in (ord("q"), ord("Q"), 27, curses.KEY_F10):
            return 0
        if ch == 9:
            state.focus = "details" if state.focus == "list" else "list"
            continue
        if ch == ord("o"):
            _open_flow(stdscr, state)
            continue
        if ch == ord("r"):
            if state.keystore_path and state.storepass is not None:
                try:
                    _load_keystore(state, state.keystore_path, state.storepass)
                except Exception as exc:
                    state.status = f"Reload failed: {exc}"
                    state.error = True
            continue
        if ch == ord("/"):
            value = _prompt(stdscr, "Alias filter (Esc cancels):", initial=state.filter_text)
            if value is not None:
                state.filter_text = value.strip()
                state.selected = 0
                state.alias_scroll = 0
                state.detail_scroll = 0
            continue
        if ch == ord("c"):
            state.filter_text = ""
            state.selected = 0
            state.alias_scroll = 0
            state.detail_scroll = 0
            state.status = "Filter cleared."
            state.error = False
            continue

        if state.focus == "list":
            if ch in (curses.KEY_UP, ord("k")) and aliases:
                state.selected = max(0, state.selected - 1)
                state.detail_scroll = 0
            elif ch in (curses.KEY_DOWN, ord("j")) and aliases:
                state.selected = min(len(aliases) - 1, state.selected + 1)
                state.detail_scroll = 0
            elif ch == curses.KEY_HOME:
                state.selected = 0
                state.detail_scroll = 0
            elif ch == curses.KEY_END and aliases:
                state.selected = len(aliases) - 1
                state.detail_scroll = 0
            elif ch == curses.KEY_PPAGE:
                state.selected = max(0, state.selected - 10)
                state.detail_scroll = 0
            elif ch == curses.KEY_NPAGE and aliases:
                state.selected = min(len(aliases) - 1, state.selected + 10)
                state.detail_scroll = 0
        else:
            if ch in (curses.KEY_UP, ord("k")):
                state.detail_scroll = max(0, state.detail_scroll - 1)
            elif ch in (curses.KEY_DOWN, ord("j")):
                state.detail_scroll += 1
            elif ch == curses.KEY_PPAGE:
                state.detail_scroll = max(0, state.detail_scroll - 10)
            elif ch == curses.KEY_NPAGE:
                state.detail_scroll += 10
            elif ch == curses.KEY_HOME:
                state.detail_scroll = 0
            elif ch == curses.KEY_END:
                state.detail_scroll = 10**9


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jksnav-tui",
        description="Interactive TUI for browsing JKS keystores.",
    )
    parser.add_argument("keystore", nargs="?", help="Path to JKS keystore")
    parser.add_argument("-keystore", dest="keystore_opt", help="Path to JKS keystore")
    parser.add_argument("-storepass", dest="storepass", help="Keystore password")
    args = parser.parse_args(argv)
    keystore = args.keystore_opt or args.keystore
    return curses.wrapper(_run, keystore, args.storepass)


if __name__ == "__main__":
    raise SystemExit(main())
