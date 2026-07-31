.PHONY: validate test check

validate:
	python -m vheatm_control.validator --root .

test:
	pytest

check: validate test
