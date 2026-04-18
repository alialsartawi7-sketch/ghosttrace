# Contributing to GhostTrace

Thank you for your interest in improving GhostTrace! This guide will help you get started.

## Adding a New Tool

Adding a tool requires only 3 steps:

### 1. Create the adapter

Create `tools/my_tool.py`:

```python
from tools.base import ToolAdapter

class MyToolAdapter(ToolAdapter):
    name = "MyTool"
    cmd = "mytool"              # system command
    result_type = "email"       # email | username | metadata | subdomain | phone | dns | ssl | whois | dork
    description = "What it does"

    def build_command(self, target, **opts):
        cmd = [self.cmd, target]
        if opts.get("tor"):
            cmd.append("--proxy")
        return cmd

    def parse_line(self, line, context):
        results = []
        if "FOUND:" in line:
            results.append({
                "value": line.split("FOUND:")[1].strip(),
                "source": self.name,
                "type": self.result_type,
                "confidence": 0.8
            })
        return results

    # Optional: inject API keys
    def get_env(self):
        return {"MY_API_KEY": "..."}
```

### 2. Register it

In `tools/registry.py`:

```python
from tools.my_tool import MyToolAdapter
# Inside ToolRegistry.init():
cls.register(MyToolAdapter)
```

### 3. Allow in CLI

In `config.py`:

```python
ALLOWED_TOOLS = {..., "mytool"}
```

That's it — the tool works across all modules, CLI, reports, and graph.

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific file
pytest tests/test_validators.py -v

# With coverage
pip install pytest-cov
pytest tests/ --cov=. --cov-report=term-missing
```

## Code Style Rules

| Rule | Example |
|------|---------|
| No bare `except:` | Use `except Exception:` |
| Use validators for all user input | `Validators.domain(value)` |
| Log with `utils.logger`, not `print()` | `log.info("msg")` |
| Type hints on public methods | `def scan(host: str) -> dict:` |
| Confidence must be dynamic | Don't hardcode — base on data quality |

## Project Structure

```
tools/       → Tool adapters (one file per tool)
core/        → Scanner engine, differ
api/         → Flask routes
recon/       → Active recon + risk engine
intelligence/→ Correlator + scoring
reports/     → PDF/HTML report generator
utils/       → Validators, security, logging
tests/       → pytest test files
```

## Submitting Changes

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-tool`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Commit: `git commit -m "Add MyTool adapter"`
6. Push: `git push origin feature/my-tool`
7. Open a Pull Request

## Security

- Never commit API keys or credentials
- All user input must pass through `utils/validators.py`
- Use whitelist validation, not blacklist
- Test path traversal scenarios

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Kali/OS version and Python version
- Console error output (if any)
