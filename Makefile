.PHONY: validate plan test check

validate:
	python -m vheatm_control.validator --root .

plan:
	python -m vheatm_control.evaluator --root . --context examples/context-low-risk.yaml

test:
	pytest

check: validate plan test
