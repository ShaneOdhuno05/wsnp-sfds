"""A small coloured console logger shared across the codebase.

``Log.info`` / ``warning`` / ``error`` / ``fatal`` / ``debug`` each print a level-tagged,
colour-coded line; debug output is gated behind the module-level ``log_level``. Setting the
module-level ``write`` flag additionally appends a timestamped, style-stripped copy of every
line to ``console.log``.
"""

from enum import IntEnum, StrEnum
from datetime import datetime
import re


class Style(StrEnum):
    """ANSI escape codes used to colour and style log output."""

    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    STRIKE = "\033[9m"
    HIGHLIGHT = "\033[7m"
    UNDERLINE = "\033[4m"
    ITALIC = "\033[3m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"


class LogType(IntEnum):
    """Severity levels, ordered so ``log_level`` can gate the noisier ones."""

    INFO = 0
    WARNING = 1
    ERROR = 2
    FATAL = 3
    DEBUG = 4


log_level = LogType.INFO  # debug lines print only while log_level >= DEBUG
write: bool = False  # when True, also append style-stripped lines to console.log


class Log:
    @classmethod
    def _strip_style(cls, message: str) -> str:
        """Strip ANSI styling and bracket bare level names, for the plain-text log file."""
        for style in Style:
            style = re.sub(r"\[", "\\[", style)
            message = re.sub(style, "", message)
        for log in LogType:
            message = re.sub(log.name, f"[{log.name}]", message)
        return message

    @classmethod
    def _write(cls, log_type: str, log_message: str) -> None:
        """Print a line, and (when ``write`` is set) append a timestamped, style-stripped copy to file."""
        print(log_type + log_message)
        if write:
            log_type = f"{datetime.now().strftime('[%Y-%m-%d][%H:%M:%S]')}{Log._strip_style(log_type)}"
            log_message = re.sub(
                "\\n", f"\n{' ' * len(log_type)}", Log._strip_style(log_message)
            )
            with open(file="console.log", mode="a", newline="\n") as f:
                f.write(log_type + log_message + "\n")

    @classmethod
    def _emit(cls, color: Style, level: LogType, message: tuple[object, ...]) -> None:
        """Format and write one line: a coloured, padded level tag followed by the joined message."""
        tag = f"{color}{level.name}{Style.ENDC}:{' ' * (9 - len(level.name))}"
        Log._write(tag, " ".join(str(arg).strip(" ") for arg in message))

    @classmethod
    def info(cls, *message: object) -> None:
        Log._emit(Style.GREEN, LogType.INFO, message)

    @classmethod
    def warning(cls, *message: object) -> None:
        Log._emit(Style.YELLOW, LogType.WARNING, message)

    @classmethod
    def error(cls, *message: object) -> None:
        Log._emit(Style.RED, LogType.ERROR, message)

    @classmethod
    def fatal(cls, *message: object) -> None:
        Log._emit(Style.MAGENTA, LogType.FATAL, message)

    @classmethod
    def debug(cls, *message: object) -> None:
        if log_level >= LogType.DEBUG:
            Log._emit(Style.CYAN, LogType.DEBUG, message)
