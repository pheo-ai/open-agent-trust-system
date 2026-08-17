PYTHON ?= python3

.PHONY: test demo validate clean

test:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

demo:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m reference_runtime.demo

validate:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m validator.cli policy examples/coding-agent/policy.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m validator.cli policy examples/invoice-exception/policy.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m validator.cli policy examples/literature-screening/policy.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m validator.cli policy examples/marketing-review/policy.json
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m validator.cli action_receipt examples/coding-agent/receipt.signed.json

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
