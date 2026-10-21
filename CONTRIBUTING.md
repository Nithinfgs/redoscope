# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
mypy src
```

Guidelines:

- Keep runtime dependencies at zero (standard library only).
- A new detection rule needs a test showing a pattern it flags **and** a similar safe pattern it
  does not flag. If the rule can fire on safe code, the verifier must be able to refute it.
- Never mark a finding `confirmed` without a measurement from the real engine.
- Node is optional; tests that need it skip when it is missing.
