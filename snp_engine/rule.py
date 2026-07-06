"""Parsing and evaluation of a single SN P firing rule.

A rule has the textual form ``guard / consumed -> produced ; delay`` (with several
shorthands) — for example ``a^{3}/a^{2} -> a; 0`` reads as "when at least three spikes
match the guard, consume two and emit one with no delay". ``Rule.parse_rule`` turns such a
string into a ``Rule``, and ``Rule.activate`` then reports, for a given spike count,
whether the rule fires and with what effect.
"""

from __future__ import annotations
from dataclasses import dataclass
from logger import Log, Style
import re


@dataclass(frozen=True)
class Rule:
    """A parsed firing rule.

    Attributes:
        _raw: the original rule text, kept for display and history.
        _bound: a regular expression (over a string of ``a``s) that the current spike count
            must match for the rule to be applicable.
        _consumption: spikes consumed when the rule fires, or ``-1`` for a "white-hole" rule
            that consumes whatever is currently present.
        _production: spikes produced when the rule fires (``0`` for a forgetting rule).
        _delay: ticks to wait before releasing the produced spikes.
    """

    _raw: str
    _bound: str
    _consumption: int
    _production: int
    _delay: int

    def __repr__(self) -> str:
        return self._raw

    def activate(self, spikes: int) -> tuple[int, int, int] | None:
        """Evaluate the rule against a spike count.

        Returns ``(consumed, produced, delay)`` if the rule is applicable, or ``None`` if
        its guard does not match. A white-hole rule (``_consumption == -1``) consumes the
        entire current count.
        """
        if re.match(self._bound, "a" * spikes) is None:
            return None
        consumed = self._consumption if self._consumption > -1 else spikes
        return consumed, self._production, self._delay

    @classmethod
    def validate(cls, rule: str) -> re.Match[str]:
        """Match a rule string against the rule grammar and return the regex match.

        In plain terms the grammar — captured by the named groups in the pattern — is::

            [ guard / ] consumption  ( -> | \\to | \\rightarrow )  ( production ; delay | 0 | \\lambda )

        The consumption term is a count (``a^{n}``), a single ``a``, or a white-hole marker
        (``a+`` / ``a^{all}``); the production term gives the spikes emitted and the delay;
        ``0`` marks a forgetting rule and ``\\lambda`` an empty output. A rule that does not
        match is a syntax error.
        """
        pattern = r"^((?P<bound>.*)\/)?(?P<consumption_bound>[a-z](\^((?P<consumed_single>[^\D])|({(?P<consumed_multiple>[1-9]|[1-9][0-9]+)}))|(?P<white_hole>\^{all}|\+)?)?)\s*(\\rightarrow|\\to|->)\s*(?P<production>([a-z]((\^((?P<produced_single>[^0,1,\D])|({(?P<produced_multiple>[2-9]|[1-9][0-9]+]*)})))?\s*;\s*(?P<delay>[0-9]|[1-9][0-9]*))|(?P<forgot>0)|(?P<lambda>\\lambda)))$"
        result = re.match(pattern, rule)
        if result is None:
            Log.error("Invalid rule: ", Style.RED + rule + Style.ENDC)
            raise SyntaxError(f"Invalid rule: {Style.RED + rule + Style.ENDC}")
        return result

    @classmethod
    def parse_rule(cls, raw: str) -> Rule:
        """Parse a raw rule string into a ``Rule``, deriving its consumption, production and delay.

        Handles white-hole rules (consume-all) and forgetting / ``\\lambda`` rules (produce
        nothing). Raises ``SyntaxError`` on an invalid rule, or if a non-white-hole rule
        would produce more spikes than it consumes.
        """
        result = cls.validate(raw)

        forgetting = bool(result.group("forgot") or result.group("lambda"))
        white_hole = bool(result.group("white_hole"))

        consumption = (
            result.group("consumed_multiple") or result.group("consumed_single") or 1
            if not white_hole
            else -1
        )
        production = (
            result.group("produced_multiple") or result.group("produced_single") or 1
            if not forgetting
            else 0
        )
        delay = int(result.group("delay") or 1 if not forgetting else 0)

        consumption = int(consumption)
        production = int(production)

        if not white_hole and production > consumption:
            Log.error(
                "Invalid rule: ",
                Style.RED + raw + Style.ENDC,
                "Production is greater than the consumption!",
            )
            raise SyntaxError(
                f"Invalid rule: {Style.RED + raw + Style.ENDC}. Production is greater than the consumption!"
            )

        bound = result.group("bound") or result.group("consumption_bound")
        return Rule(raw, cls._parse_bound(bound), consumption, production, delay)

    @classmethod
    def _parse_bound(cls, bound: str) -> str:
        """Convert a guard from rule notation into an anchored regex over a string of ``a``s.

        Strips the ``^{...}`` count wrappers and normalises the star/plus markers
        (``\\ast``, ``{*}``, ``{+}``) so the result can be matched directly in ``activate``.
        """
        bound = re.sub("\\^(\\d)", "^{\\1}", bound).replace("^", "")
        bound = re.sub(r"\{\s*\\ast\s*\}", "*", bound)
        bound = re.sub(r"\{\s*\*\s*\}", "*", bound)
        bound = re.sub(r"\{\s*\+\s*\}", "+", bound)
        bound = re.sub(r"\\ast", "*", bound)
        return f"^{bound}$"
