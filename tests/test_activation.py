from vheatm_control.activation import TruthValue, compile_activation


def test_precedence_and_parentheses() -> None:
    expression = compile_activation("mode == full or mode == standard and target_tier == 3")
    assert expression.evaluate({"mode": "standard", "target_tier": 2}) is TruthValue.FALSE
    assert expression.evaluate({"mode": "standard", "target_tier": 3}) is TruthValue.TRUE


def test_unknown_uses_strong_kleene_logic() -> None:
    expression = compile_activation("safety_critical == yes or blast_radius >= 3")
    assert expression.evaluate({"declarations": {"safety_critical": "unknown"}, "blast_radius": 4}) is TruthValue.TRUE
    assert expression.evaluate({"declarations": {"safety_critical": "unknown"}, "blast_radius": 1}) is TruthValue.UNKNOWN


def test_short_circuit_false_and_unknown() -> None:
    expression = compile_activation("context_mode == enterprise and missing_field == yes")
    assert expression.evaluate({"context_mode": "single"}) is TruthValue.FALSE
    assert expression.evaluate({"context_mode": "enterprise"}) is TruthValue.UNKNOWN


def test_references_are_explicit() -> None:
    expression = compile_activation("mode in [standard, full] and target_tier >= 2")
    assert expression.references == frozenset({"mode", "target_tier"})
