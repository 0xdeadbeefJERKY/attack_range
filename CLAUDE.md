# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Splunk Attack Range v5 — builds instrumented cloud environments (AWS, Azure, GCP, Ludus), simulates attacks via Atomic Red Team, and forwards telemetry into Splunk for detection development. Runs as a web app + REST API + CLI, all orchestrated via Docker Compose.

## Common Commands

### Python tests
```bash
pytest tests/                        # run all tests
pytest tests/test_aws_provider.py    # run a single test file
pytest tests/test_aws_provider.py::TestAWSProvider::test_method -v  # single test
```
Tests use `moto` for AWS mocking. Fixtures are in `tests/conftest.py` (mock_logger, aws_credentials, aws_config, aws_backend_context).

### Frontend (Astro app in `app/`)
```bash
cd app && npm install                # install deps
cd app && npm run dev                # dev server on :4321
cd app && npm run build              # production build
cd app && npx playwright test        # E2E tests
cd app && npx playwright test --ui   # E2E tests with UI
```

### API server
```bash
cd api && python app.py              # Flask dev server on :4000
```
Swagger docs at `http://localhost:4000/openapi/swagger`.

### Full stack via Docker
```bash
docker compose -f docker/docker-compose.yml up          # API + app
docker compose --profile cli -f docker/docker-compose.yml run --rm attack_range build -t aws/splunk_minimal_aws  # CLI
```

### CLI directly
```bash
python attack_range.py build -t aws/splunk_minimal_aws
python attack_range.py destroy -id <attack_range_id>
python attack_range.py simulate -id <attack_range_id> -t T1003.001
python attack_range.py share -id <attack_range_id>
```

## Architecture

### Two-phase build process
1. **VPN phase**: Deploy WireGuard VPN infrastructure, generate client config, wait for user to connect.
2. **Lab phase**: After VPN connected, deploy lab resources (Splunk, Windows/Linux servers, AD, Zeek, etc.) via Terraform + Ansible.

### Core module: `attack_range/`
- **`attack_range_controller.py`** — Thin orchestrator; delegates to managers and cloud providers.
- **`managers/`** — Domain-specific logic:
  - `config_manager.py` — Config validation, ID generation, file I/O
  - `terraform_manager.py` — Terraform init/apply/destroy/output
  - `ansible_manager.py` — Inventory, playbook generation, execution
  - `ssh_manager.py` — SSH key pair generation and upload
  - `backend_manager.py` — Remote state storage (S3/Azure Storage/GCS)
- **`cloud_providers/`** — Cloud abstractions extending `BaseCloudProvider`:
  - `aws_provider.py`, `azure_provider.py`, `gcp_provider.py`, `ludus_provider.py`
  - Ludus provider bypasses Terraform entirely, using the Ludus API directly.

### API: `api/`
- `app.py` — Flask-OpenAPI3 server with Pydantic models (`models.py`, `cloud_fields.py`).
- Long-running operations run in background threads; clients poll status endpoints.

### Frontend: `app/`
- Astro 5 SSR app. Pages for template browsing and running attack ranges.
- Communicates with the API on port 4000.

### Infrastructure-as-code: `terraform/`
- Per-provider modules: `terraform/{aws,azure,gcp,ludus}/`
- Ansible playbooks and roles: `terraform/ansible/`

### Templates: `templates/`
- YAML templates per provider in `templates/{aws,azure,gcp,ludus}/` define range configurations.
- Runtime configs saved to `config/<attack_range_id>.yml`.

## Key Entry Points

| Entry point | File | Purpose |
|---|---|---|
| CLI | `attack_range.py` | build/destroy/simulate/share commands |
| API | `api/app.py` | REST API with OpenAPI docs |
| Web UI | `app/src/pages/` | Astro SSR frontend |
| Controller | `attack_range/attack_range_controller.py` | Core orchestration |

## Adding a New Cloud Provider

1. Create `attack_range/cloud_providers/<provider>_provider.py` extending `BaseCloudProvider`
2. Register in `AttackRangeController._init_cloud_provider()`
3. Add Terraform modules in `terraform/<provider>/`
4. Add templates in `templates/<provider>/`

## Git Workflow

- Main branch: `develop`
- PRs target `develop`
- Python 3.10+, Poetry for dependency management (`pyproject.toml`)
- Dev deps: pytest, moto
