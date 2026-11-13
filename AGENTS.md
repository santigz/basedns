# Project Guidelines & Testing Policy

## Testing Policy (Docker Only)

- **Never run tests natively on the host** (do not run `pytest`, `python -m unittest`, `node --test`, `npm test`, etc. directly on the host machine).
- **Never run tests inside or against the production `basedns` container.**
- **Always run tests in ephemeral Docker containers** created just-in-time via the `test` profile in `compose.yml`:
  - Python integration and unit tests:
    ```bash
    docker compose --profile test run --rm tests
    ```
  - JavaScript unit tests:
    ```bash
    docker compose --profile test run --rm js-tests
    ```
- **If Docker is missing or unavailable**: Before attempting any test run, verify that `docker` is installed and the daemon is reachable (e.g., `docker info`). If Docker is not installed or the daemon is not running, **stop immediately and warn/ask the user to install or start Docker** instead of falling back to native host execution.
