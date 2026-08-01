from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Any, Iterable, Mapping


class ActivationError(ValueError):
    """Base error for activation expressions."""


class ActivationSyntaxError(ActivationError):
    """Raised when an activation expression is not in the supported DSL."""


class ActivationEvaluationError(ActivationError):
    """Raised when an expression is valid but cannot be safely evaluated."""


class TruthValue(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @classmethod
    def from_bool(cls, value: bool) -> "TruthValue":
        return cls.TRUE if value else cls.FALSE


_UNKNOWN = object()


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    offset: int


_TOKEN_RE = re.compile(
    r"(?P<SPACE>\s+)"
    r"|(?P<NUMBER>-?(?:\d+(?:\.\d*)?|\.\d+))"
    r"|(?P<STRING>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    r"|(?P<OP>==|!=|>=|<=|>|<)"
    r"|(?P<LPAREN>\()|(?P<RPAREN>\))"
    r"|(?P<LBRACKET>\[)|(?P<RBRACKET>\])|(?P<COMMA>,)"
    r"|(?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)"
)


class Expr:
    def evaluate(self, context: Mapping[str, Any]) -> TruthValue:
        raise NotImplementedError

    def references(self) -> frozenset[str]:
        return frozenset()


@dataclass(frozen=True)
class BooleanLiteral(Expr):
    value: bool

    def evaluate(self, context: Mapping[str, Any]) -> TruthValue:
        return TruthValue.from_bool(self.value)


@dataclass(frozen=True)
class Reference:
    name: str


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class ListLiteral:
    items: tuple[Literal, ...]


Value = Reference | Literal | ListLiteral


@dataclass(frozen=True)
class Comparison(Expr):
    left: Reference
    operator: str
    right: Value

    def references(self) -> frozenset[str]:
        refs = {self.left.name}
        if isinstance(self.right, Reference):
            refs.add(self.right.name)
        return frozenset(refs)

    def evaluate(self, context: Mapping[str, Any]) -> TruthValue:
        left = _resolve_value(self.left, context)
        right = _resolve_value(self.right, context)
        if left is _UNKNOWN or right is _UNKNOWN:
            return TruthValue.UNKNOWN
        if isinstance(right, list) and any(item is _UNKNOWN for item in right):
            return TruthValue.UNKNOWN
        try:
            if self.operator == "==":
                return TruthValue.from_bool(left == right)
            if self.operator == "!=":
                return TruthValue.from_bool(left != right)
            if self.operator == ">=":
                return TruthValue.from_bool(left >= right)
            if self.operator == "<=":
                return TruthValue.from_bool(left <= right)
            if self.operator == ">":
                return TruthValue.from_bool(left > right)
            if self.operator == "<":
                return TruthValue.from_bool(left < right)
            if self.operator == "in":
                if not isinstance(right, list):
                    raise ActivationEvaluationError("right operand of 'in' must be a list")
                return TruthValue.from_bool(left in right)
            if self.operator == "not in":
                if not isinstance(right, list):
                    raise ActivationEvaluationError("right operand of 'not in' must be a list")
                return TruthValue.from_bool(left not in right)
        except TypeError as exc:
            raise ActivationEvaluationError(
                f"incompatible values for {self.operator!r}: {type(left).__name__} and {type(right).__name__}"
            ) from exc
        raise ActivationEvaluationError(f"unsupported operator: {self.operator}")


@dataclass(frozen=True)
class BooleanOperation(Expr):
    operator: str
    left: Expr
    right: Expr

    def references(self) -> frozenset[str]:
        return self.left.references() | self.right.references()

    def evaluate(self, context: Mapping[str, Any]) -> TruthValue:
        left = self.left.evaluate(context)
        if self.operator == "and":
            if left is TruthValue.FALSE:
                return TruthValue.FALSE
            right = self.right.evaluate(context)
            if right is TruthValue.FALSE:
                return TruthValue.FALSE
            if left is TruthValue.TRUE and right is TruthValue.TRUE:
                return TruthValue.TRUE
            return TruthValue.UNKNOWN
        if self.operator == "or":
            if left is TruthValue.TRUE:
                return TruthValue.TRUE
            right = self.right.evaluate(context)
            if right is TruthValue.TRUE:
                return TruthValue.TRUE
            if left is TruthValue.FALSE and right is TruthValue.FALSE:
                return TruthValue.FALSE
            return TruthValue.UNKNOWN
        raise ActivationEvaluationError(f"unsupported boolean operator: {self.operator}")


def _resolve_reference(name: str, context: Mapping[str, Any]) -> Any:
    if name in context:
        value = context[name]
    else:
        declarations = context.get("declarations", {})
        value = declarations.get(name, _UNKNOWN) if isinstance(declarations, Mapping) else _UNKNOWN
    if value is None or value == "unknown":
        return _UNKNOWN
    return value


def _resolve_value(value: Value, context: Mapping[str, Any]) -> Any:
    if isinstance(value, Reference):
        return _resolve_reference(value.name, context)
    if isinstance(value, Literal):
        return value.value
    return [_resolve_value(item, context) for item in value.items]


def _tokenize(expression: str) -> list[Token]:
    tokens: list[Token] = []
    offset = 0
    while offset < len(expression):
        match = _TOKEN_RE.match(expression, offset)
        if not match:
            raise ActivationSyntaxError(f"unsupported token at offset {offset}: {expression[offset:offset + 12]!r}")
        kind = match.lastgroup
        if kind is None:
            raise ActivationSyntaxError(f"token kind is unavailable at offset {offset}")
        if kind != "SPACE":
            tokens.append(Token(kind, match.group(), offset))
        offset = match.end()
    tokens.append(Token("EOF", "", len(expression)))
    return tokens


class _Parser:
    def __init__(self, expression: str) -> None:
        self.expression = expression
        self.tokens = _tokenize(expression)
        self.index = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def advance(self) -> Token:
        token = self.current
        self.index += 1
        return token

    def accept(self, kind: str, value: str | None = None) -> Token | None:
        token = self.current
        if token.kind == kind and (value is None or token.value == value):
            self.index += 1
            return token
        return None

    def expect(self, kind: str, value: str | None = None) -> Token:
        token = self.accept(kind, value)
        if token is None:
            expected = value if value is not None else kind
            raise ActivationSyntaxError(
                f"expected {expected!r} at offset {self.current.offset}, got {self.current.value!r}"
            )
        return token

    def parse(self) -> Expr:
        result = self.parse_or()
        self.expect("EOF")
        return result

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.current.kind == "IDENT" and self.current.value == "or":
            self.advance()
            left = BooleanOperation("or", left, self.parse_and())
        return left

    def parse_and(self) -> Expr:
        left = self.parse_primary()
        while self.current.kind == "IDENT" and self.current.value == "and":
            self.advance()
            left = BooleanOperation("and", left, self.parse_primary())
        return left

    def parse_primary(self) -> Expr:
        if self.accept("LPAREN"):
            expression = self.parse_or()
            self.expect("RPAREN")
            return expression
        if self.current.kind == "IDENT" and self.current.value in {"always", "true", "false"}:
            value = self.advance().value
            return BooleanLiteral(value != "false")
        return self.parse_comparison()

    def parse_comparison(self) -> Expr:
        left_token = self.expect("IDENT")
        if left_token.value in {"and", "or", "in", "not"}:
            raise ActivationSyntaxError(f"reserved keyword cannot be a reference: {left_token.value!r}")
        left = Reference(left_token.value)

        if self.current.kind == "OP":
            operator = self.advance().value
        elif self.current.kind == "IDENT" and self.current.value == "in":
            operator = self.advance().value
        elif self.current.kind == "IDENT" and self.current.value == "not":
            self.advance()
            self.expect("IDENT", "in")
            operator = "not in"
        else:
            raise ActivationSyntaxError(
                f"expected comparison operator at offset {self.current.offset}, got {self.current.value!r}"
            )
        return Comparison(left, operator, self.parse_value())

    def parse_value(self) -> Value:
        token = self.current
        if token.kind == "NUMBER":
            self.advance()
            return Literal(float(token.value) if "." in token.value else int(token.value))
        if token.kind == "STRING":
            self.advance()
            return Literal(ast.literal_eval(token.value))
        if token.kind == "IDENT":
            self.advance()
            if token.value == "null":
                return Literal(None)
            if token.value == "true":
                return Literal(True)
            if token.value == "false":
                return Literal(False)
            return Literal(token.value)
        if self.accept("LBRACKET"):
            items: list[Literal] = []
            if not self.accept("RBRACKET"):
                while True:
                    value = self.parse_value()
                    if not isinstance(value, Literal):
                        raise ActivationSyntaxError("nested lists are not supported")
                    items.append(value)
                    if self.accept("COMMA"):
                        continue
                    self.expect("RBRACKET")
                    break
            return ListLiteral(tuple(items))
        raise ActivationSyntaxError(f"expected value at offset {token.offset}, got {token.value!r}")


@dataclass(frozen=True)
class CompiledActivation:
    expression: str
    ast: Expr

    @property
    def references(self) -> frozenset[str]:
        return self.ast.references()

    def evaluate(self, context: Mapping[str, Any]) -> TruthValue:
        return self.ast.evaluate(context)

    def unknown_references(self, context: Mapping[str, Any]) -> tuple[str, ...]:
        return tuple(sorted(name for name in self.references if _resolve_reference(name, context) is _UNKNOWN))


@lru_cache(maxsize=256)
def compile_activation(expression: str) -> CompiledActivation:
    normalized = expression.strip()
    if not normalized:
        raise ActivationSyntaxError("activation expression cannot be empty")
    return CompiledActivation(normalized, _Parser(normalized).parse())


def referenced_fields(expressions: Iterable[str]) -> frozenset[str]:
    fields: set[str] = set()
    for expression in expressions:
        fields.update(compile_activation(expression).references)
    return frozenset(fields)

ALLOWED_CONTEXT_FIELDS = frozenset(
    {
        "mode",
        "target_tier",
        "context_mode",
        "mandatory_findings",
        "blast_radius",
        "write_chain_components",
        "self_audit",
        "ai_integrated",
        "ai_executor",
        "async_worker",
        "safety_critical",
        "financial_path",
    }
)
