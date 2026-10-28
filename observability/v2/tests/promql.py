"""The vector selectors of a PromQL expression, without a PromQL parser.

A small lexer, enough for the expressions of observability/v2 and tested on each construct they use
(test_promql.py): string literals, label matchers, ranges, offsets, grouping and matching clauses, aggregation
operators, functions and Grafana's variables. Every identifier that is not a function call, a keyword or an
aggregation operator is a metric name; a "{...}" after it holds its label matchers.
"""
import re

KEYWORDS = {"by", "without", "on", "ignoring", "group_left", "group_right", "bool", "offset", "and", "or",
            "unless", "inf", "nan", "atan2", "start", "end"}
AGGREGATIONS = {"sum", "min", "max", "avg", "group", "stddev", "stdvar", "count", "count_values", "bottomk",
                "topk", "quantile", "limitk", "limit_ratio"}
CLAUSES = {"by", "without", "on", "ignoring", "group_left", "group_right"}
_TOKEN = re.compile(r'''
    (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`]*`)
  | (?P<variable>\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*))
  | (?P<number>[0-9][0-9a-zA-Z.]*)
  | (?P<ident>[a-zA-Z_:][a-zA-Z0-9_:]*)
  | (?P<lbrace>\{) | (?P<rbrace>\}) | (?P<lparen>\() | (?P<rparen>\)) | (?P<lbracket>\[) | (?P<rbracket>\])
  | (?P<space>\s+)
  | (?P<other>.)
''', re.VERBOSE)
_MATCHER = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*("(?:[^"\\]|\\.)*")')


def _tokens(expr):
    """(kind, text, start, end) of every token but white space."""
    return [(m.lastgroup, m.group(), m.start(), m.end()) for m in _TOKEN.finditer(expr) if m.lastgroup != "space"]


def _unquote(literal):
    return re.sub(r"\\(.)", r"\1", literal[1:-1])


def _parse_matchers(body):
    return [(label, op, _unquote(value)) for label, op, value in _MATCHER.findall(body)]


def selectors(expr):
    """[(name or None, [(label, operator, value)])] for every vector selector of expr, in order. A selector
    written {__name__=~"x"} has the name None and the matcher ("__name__", "=~", "x")."""
    tokens = _tokens(expr)
    out, i = [], 0
    while i < len(tokens):
        kind, text = tokens[i][:2]
        following = tokens[i + 1] if i + 1 < len(tokens) else (None, None, None, None)
        if kind == "lbracket":                       # a range or subquery: [5m], [$__rate_interval], [1h:5m]
            while i < len(tokens) and tokens[i][0] != "rbracket":
                i += 1
        elif kind == "ident" and text in CLAUSES and following[0] == "lparen":
            while i < len(tokens) and tokens[i][0] != "rparen":
                i += 1
        elif kind == "ident" and text == "offset":
            i += 1                                   # the duration after it
        elif kind == "ident" and text not in KEYWORDS and text not in AGGREGATIONS and following[0] != "lparen":
            body = ""
            if following[0] == "lbrace":
                i, body = _braced(expr, tokens, i + 1)
            out.append((text, _parse_matchers(body)))
        elif kind == "lbrace":
            i, body = _braced(expr, tokens, i)
            out.append((None, _parse_matchers(body)))
        i += 1
    return out


def _braced(expr, tokens, opening):
    """(index of the closing brace, the text between) for the "{" at tokens[opening]."""
    closing = opening
    while closing < len(tokens) and tokens[closing][0] != "rbrace":
        closing += 1
    end = tokens[closing][2] if closing < len(tokens) else len(expr)
    return closing, expr[tokens[opening][3]:end]


def names(expr):
    """The metric names expr selects, sorted. {__name__="x"} counts as x; {__name__=~"x(_total)?"} as
    "re:x(_total)?", for the caller to match against the names it knows."""
    found = set()
    for name, matchers in selectors(expr):
        if name is not None:
            found.add(name)
        for label, op, value in matchers:
            if label == "__name__":
                found.add(value if op == "=" else f"re:{value}")
    return sorted(found)


def matchers(expr):
    """(metric name or None, label, operator, value) for every label matcher of every selector in expr."""
    return [(name, label, op, value) for name, found in selectors(expr) for label, op, value in found]


def grouping_labels(expr):
    """The labels named in by/without/on/ignoring/group_left/group_right clauses."""
    tokens = _tokens(expr)
    out = set()
    for i, (kind, text, _, _) in enumerate(tokens):
        if kind == "ident" and text in CLAUSES and i + 1 < len(tokens) and tokens[i + 1][0] == "lparen":
            j = i + 2
            while j < len(tokens) and tokens[j][0] != "rparen":
                if tokens[j][0] == "ident":
                    out.add(tokens[j][1])
                j += 1
    return out
