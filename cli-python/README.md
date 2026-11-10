# header-auditor (Python CLI)

The original zero-dependency Python CLI. It grades a website's HTTP security
headers and prints what to fix. See the [root README](../README.md) for the
full list of checks and the project roadmap.

```bash
cd cli-python
pip install -e ".[dev]"
header-auditor https://your-site.example --min-grade B
pytest -q
bandit -q -r header_auditor
```
