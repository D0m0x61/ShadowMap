# Contributing

## Setup

```bash
git clone https://github.com/D0m0x61/ShadowMap.git
cd ShadowMap
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt && pip install -e .
cp .env.example .env       # fill in SHODAN_API_KEY and ABUSEIPDB_API_KEY at minimum
```

---

## Conventions

One module = one file = one public function. Each file in `modules/` exposes a single function that the CLI calls. It must work standalone — importable and callable without the CLI.

Use the shared utilities:
- `get_session()` from `utils/http_client.py`
- `RateLimiter` from `utils/rate_limiter.py`
- `get_logger(__name__)` from `utils/logger.py`
- `Config.*` from `config.py` for all URLs, keys, and delays

Type hints on every public function, return type included.

---

## Adding a module

1. Create `shadowmap/modules/your_module.py`
2. Implement the primary function with type hints
3. Wire it into `cli.py`: add an entry in `_pipeline()` and a choice in `--modules`
4. Add tests in `tests/test_modules.py` — mock the network, test the logic
5. Update the module table in `README.md` and the data flow in `docs/architecture.md`

---

## Tests

```bash
pytest tests/ -v
```

---

## Pull requests

- One feature or fix per PR
- Never commit `.env` or real API keys
- All tests must pass
- Update docs if behavior changes
