"""
A tiny, safe boolean query language for the "message contains" filter.

Wireshark-style expressions over case-insensitive substring terms::

    "client_mac" && assoc
    ("client_mac" && assoc) || ("client_mac" && disassoc)
    wifi && (assoc || disassoc)

Grammar (``||`` is lowest precedence, ``&&`` binds tighter, parentheses group)::

    or   := and ('||' and)*
    and  := atom ('&&' atom)*
    atom := '(' or ')' | TERM

A TERM is a double/single-quoted string (which may contain spaces and the
operator characters literally) or a bare run of characters with no whitespace,
parentheses, or ``&&`` / ``||``. Matching is case-insensitive substring
containment. There is no ``eval`` — everything is a hand-written tokenizer +
recursive-descent parser, so an arbitrary user string can never execute code.
"""

from __future__ import annotations

from typing import Optional


def is_expression(query: str) -> bool:
    """True when the query uses boolean operators / grouping, as opposed to a
    plain term or a legacy ``|``-separated list."""
    return "&&" in query or "||" in query or "(" in query


def _tokenize(s: str) -> list[tuple[str, str]]:
    """Split ``s`` into (kind, value) tokens. Kinds: '(', ')', '&&', '||',
    'term'. Unterminated quotes consume the rest of the string as a term."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c == "(" or c == ")":
            tokens.append((c, ""))
            i += 1
            continue
        if s.startswith("&&", i):
            tokens.append(("&&", ""))
            i += 2
            continue
        if s.startswith("||", i):
            tokens.append(("||", ""))
            i += 2
            continue
        if c == '"' or c == "'":
            j = s.find(c, i + 1)
            if j == -1:
                tokens.append(("term", s[i + 1:]))
                break
            tokens.append(("term", s[i + 1:j]))
            i = j + 1
            continue
        # Bare term: read up to the next operator, parenthesis, or quote.
        # Internal whitespace is KEPT so an unquoted multi-word run is one
        # phrase term (e.g. `wl2.1 send assoc`); ends are trimmed. Use `&&`
        # between words to require them separately rather than as a phrase.
        j = i
        while j < n:
            cj = s[j]
            if cj in "()\"'":
                break
            if s.startswith("&&", j) or s.startswith("||", j):
                break
            j += 1
        tokens.append(("term", s[i:j].strip()))
        i = j
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self._toks = tokens
        self._i = 0

    def _peek(self) -> Optional[str]:
        return self._toks[self._i][0] if self._i < len(self._toks) else None

    def _advance(self) -> tuple[str, str]:
        tok = self._toks[self._i]
        self._i += 1
        return tok

    def parse(self) -> tuple:
        node = self._parse_or()
        if self._i != len(self._toks):
            raise ValueError("unexpected trailing tokens")
        return node

    def _parse_or(self) -> tuple:
        nodes = [self._parse_and()]
        while self._peek() == "||":
            self._advance()
            nodes.append(self._parse_and())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def _parse_and(self) -> tuple:
        nodes = [self._parse_atom()]
        while self._peek() == "&&":
            self._advance()
            nodes.append(self._parse_atom())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def _parse_atom(self) -> tuple:
        kind = self._peek()
        if kind == "(":
            self._advance()
            node = self._parse_or()
            if self._peek() != ")":
                raise ValueError("missing closing parenthesis")
            self._advance()
            return node
        if kind == "term":
            _, val = self._advance()
            val = val.strip()
            if not val:
                raise ValueError("empty term")
            return ("term", val.casefold())
        raise ValueError(f"unexpected token: {kind}")


def parse(query: str) -> Optional[tuple]:
    """Parse ``query`` into an evaluatable AST, or ``None`` when it is empty or
    not a valid boolean expression."""
    tokens = _tokenize(query or "")
    if not tokens:
        return None
    try:
        return _Parser(tokens).parse()
    except ValueError:
        return None


def matches(node: tuple, haystack_casefolded: str) -> bool:
    """Evaluate a parsed AST against an already case-folded haystack string."""
    kind = node[0]
    if kind == "term":
        return node[1] in haystack_casefolded
    if kind == "and":
        return all(matches(child, haystack_casefolded) for child in node[1])
    # "or"
    return any(matches(child, haystack_casefolded) for child in node[1])


def terms(query: str) -> list[str]:
    """Distinct search terms in ``query`` (boolean expression or legacy
    ``|``-separated list), in first-appearance order. Used for highlighting."""
    q = (query or "").strip()
    if not q:
        return []
    raw = ([v for kind, v in _tokenize(q) if kind == "term"]
           if is_expression(q) else q.split("|"))
    out: list[str] = []
    seen: set[str] = set()
    for t in raw:
        t = t.strip()
        key = t.casefold()
        if t and key not in seen:
            seen.add(key)
            out.append(t)
    return out
