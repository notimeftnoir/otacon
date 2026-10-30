"""Interactive terminal prompts, styles, keybindings, and validators."""

from __future__ import annotations

from typing import cast

import questionary
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.shortcuts import prompt as _pt_prompt
from prompt_toolkit.validation import ValidationError, Validator

from ..utils.validate import is_valid_domain, normalize_domain

_POINTER = "[*]"
_QMARK = "›"  # noqa: RUF001


def _make_style(answer_color: str) -> questionary.Style:
    """Builds a questionary Style with the Otacon palette."""
    return questionary.Style(
        [
            ("qmark", "fg:#00d7af bold"),
            ("question", "bold fg:#afafaf"),
            ("answer", f"fg:{answer_color}"),
            ("pointer", "fg:#00d7af bold"),
            ("highlighted", "fg:#00d7af bold"),
            ("selected", f"fg:{answer_color}"),
            ("instruction", "fg:#8a8a8a"),
            ("text", f"fg:{answer_color}"),
            ("disabled", "fg:#8a8a8a italic"),
            ("validator-toolbar", "bg:#870000 fg:#ffffff"),
        ]
    )


_STYLE = _make_style("#ffffff")
_STYLE_DOMAIN = _make_style("#5fd700")


class _YNValidator(Validator):
    """Validator that accepts y/n/empty and rejects other keys."""

    def validate(self, document: Document) -> None:
        if document.text.strip().lower() not in ("y", "n", ""):
            raise ValidationError(message="Type y or n", cursor_position=len(document.text))


def _yn_bindings() -> KeyBindings:
    """Keybindings auto-submitting on y/n without pressing Enter."""
    kb = KeyBindings()

    @kb.add("y")
    @kb.add("Y")
    def _yes(event: KeyPressEvent) -> None:
        event.app.current_buffer.text = "y"
        event.app.current_buffer.validate_and_handle()

    @kb.add("n")
    @kb.add("N")
    def _no(event: KeyPressEvent) -> None:
        event.app.current_buffer.text = "n"
        event.app.current_buffer.validate_and_handle()

    return kb


def _confirm(message: str) -> bool | None:
    """Displays a stylized y/n confirmation prompt."""
    # ponytail: test hook — the guided mode's tests patch the otacon.interactive facade
    # (~80 sites), so lookups go through it. Repoint those patches to the real
    # modules and this goes; until then it is confined to triage/.
    import sys

    mod = sys.modules.get("otacon.interactive")
    if mod and hasattr(mod, "_confirm"):
        val = mod._confirm
        if val is not _confirm:
            return cast(bool | None, val(message))

    pt_prompt_fn = _pt_prompt
    if mod and hasattr(mod, "_pt_prompt"):
        p_val = mod._pt_prompt
        if p_val is not _pt_prompt:
            pt_prompt_fn = p_val

    prompt_text = FormattedText(
        [
            ("fg:#00d7af bold", "› "),  # noqa: RUF001
            ("bold fg:#afafaf", f"{message} ("),
            ("fg:#5fd700 bold", "y"),
            ("fg:#8a8a8a", "/"),
            ("fg:#ff5f5f bold", "n"),
            ("fg:#8a8a8a", ") "),
        ]
    )
    try:
        answer = pt_prompt_fn(
            prompt_text,
            validator=_YNValidator(),
            validate_while_typing=False,
            key_bindings=_yn_bindings(),
        )
        return answer.strip().lower() == "y"
    except KeyboardInterrupt:
        return None


def _validate_domain(text: str) -> bool | str:
    """Questionary validator for domain FQDN input."""
    domain = normalize_domain(text)
    if not domain:
        return "Domain cannot be empty"
    if not is_valid_domain(domain):
        return "Invalid domain (expected format: example.com)"
    return True


def _validate_limit(text: str) -> bool | str:
    """Questionary validator for non-negative result limits."""
    try:
        if int(text) < 0:
            return "Enter 0 or greater"
        return True
    except ValueError:
        return "Enter a number (0 = all)"


__all__ = [
    "_POINTER",
    "_QMARK",
    "_STYLE",
    "_STYLE_DOMAIN",
    "_YNValidator",
    "_confirm",
    "_make_style",
    "_validate_domain",
    "_validate_limit",
    "_yn_bindings",
]
