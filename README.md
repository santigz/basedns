# basedns

A lightweight self-hosted DNS platform and authoritative DNS management interface built on top of FastAPI and BIND 9.

---

## Running the Application

### 1. Build and Run via Docker Compose

To start the production service with persisted BIND configurations and backups:

```bash
docker compose up -d --build
```

This starts the container named `basedns` exposing:
- **Web UI & API:** Port `8053` (`http://localhost:8053`)
- **DNS Server (BIND9):** Port `5053` (TCP/UDP)

Persisted named volumes defined in `compose.yml`:
- `basedns-bind`: mounted at `/etc/bind`
- `basedns-bind-backups`: mounted at `/etc/bind-backups`

To view container logs:
```bash
docker compose logs -f
```

To stop the service:
```bash
docker compose down
```

---

## Running Tests

The project includes both **Python integration/security tests** (testing FastAPI and BIND 9 end-to-end) and **JavaScript unit tests** (testing zonefile parsing/generation, input validations, and UI logic).

### 1. Python Integration & Security Tests

Integration and security tests (`tests/test_integration.py`, `tests/test_origin_management.py`) interact with the FastAPI server on port 80 and BIND 9 on port 53.

To run the Python test suite in an ephemeral, isolated container without touching the production `basedns` container or its volumes:

```bash
docker compose --profile test run --rm tests
```

This command:
1. Uses the `test` profile so `docker compose up -d` never starts test services in production.
2. Spawns an ephemeral container (`--rm`) with test-only environment variables (`ROOT_DOMAIN=example.com.`, `TESTING_MODE=true`).
3. Mounts the project root to `/code` **without** mounting the production volumes (`/etc/bind` and `/etc/bind-backups`).
4. Starts FastAPI and BIND inside the container, waits until the HTTP server responds on port 80, and runs `python -m unittest discover tests -v`.

### 2. JavaScript Unit Tests

The frontend and zonefile generation tests (`tests/js/*.test.js`) use Node.js's built-in test runner (`node:test`) with zero external npm dependencies.

#### Run Against Current Code

```bash
docker compose --profile test run --rm js-tests
```

#### Run Against a Previous Git Commit

To run the current JavaScript test suite against the JS code from an earlier git commit (e.g. to verify regression fixes without modifying your working tree):

```bash
docker compose --profile test run --rm -e GIT_COMMIT=8d2a299 js-tests
# or using a relative ref:
docker compose --profile test run --rm -e GIT_COMMIT=HEAD~1 js-tests
```

---

## TODO:
- Create `user-zones` directory and others if it does not exist.
- Rename `user-tokens` to `user-api-tokens`
- Admin panel for users in `dns-admins` group for resetting user zones.
