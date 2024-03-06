"""
Pylint reporter for GitHub Actions
"""
from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING
from pylint.reporters.text import TextReporter

if TYPE_CHECKING:
    from pylint.lint.pylinter import PyLinter

levels = {
    "I": "notice",
    "C": "notice",
    "R": "notice",
    "W": "warning",
    "E": "error",
    "F": "error",
}


class ActionsReporter(TextReporter):
    """
    Reporter for GitHub Actions based on the TextReporter.
    """
    name = "actions"

    def __init__(self, *args, **kwargs):
        self.line_format = "::{level} file={path},line={line},endLine={end_line}," \
                           "title=Pylint: {msg_id} ({symbol})::{msg}"
        super().__init__(*args, **kwargs)

    def write_message(self, msg) -> None:
        self_dict = asdict(msg)
        self_dict["level"] = levels[msg.C]
        for key in ("end_line", "end_column"):
            self_dict[key] = self_dict[key] or ""

        self.writeln(self._fixed_template.format(**self_dict))


def register(linter: PyLinter):
    """
    Register the reporter with Pylint.
    """
    linter.register_reporter(ActionsReporter)
