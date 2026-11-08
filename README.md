# dns-platform

A lightweight self-hosted DNS platform and authoritative DNS management interface built on top of FastAPI and BIND 9.

---

## Running the Application

### 1. Build and Run via Docker Compose

To start the production service with persisted BIND configurations and backups:

```bash
docker compose up -d --build
```

This starts the container named `dns-platform` exposing:
- **Web UI & API:** Port `8053` (`http://localhost:8053`)
- **DNS Server (BIND9):** Port `5053` (TCP/UDP)

Persisted named volumes defined in [`compose.yml`](file:///home/santi/dev/dns-platform/compose.yml):
- `dns-platform-bind`: mounted at `/etc/bind`
- `dns-platform-bind-backups`: mounted at `/etc/bind-backups`

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

Integration and security tests interact directly with the FastAPI server on port 80 and BIND 9 on port 53.

### Running Tests in an Isolated Test Container

To run the complete test suite in a separate, isolated, ephemeral container without interfering with or mutating your production container data:

```bash
docker run --rm \
  -v "$(pwd)":/code \
  -e ROOT_DOMAIN=example.com. \
  -e TESTING_MODE=true \
  dns-platform \
  bash -c "fastapi run app/main.py --proxy-headers --port 80 & sleep 3 && python -m unittest discover tests -v"
```

This command:
1. Spawns an ephemeral test container (`--rm`).
2. Mounts the project root to `/code`.
3. Does **not** mount the production volumes (`/etc/bind` and `/etc/bind-backups`), ensuring test execution is completely sandboxed.
4. Boots up FastAPI and BIND in the background.
5. Executes the test suite (`test_integration.py`), covering zone operations, record updates, backup archive creation, and BIND 9 security hardening checks (recursion prevention, AXFR refusal, RFC 2136 refusal, and CHAOS query suppression).

### Running Tests Inside an Already Running Development Container

If you already have a running development container and wish to execute the test suite against it:

```bash
docker exec -it dns-platform python -m unittest discover tests -v
```

---

## TODO:
- Create `user-zones` directory and others if it does not exist.
- Rename `user-tokens` to `user-api-tokens`
- Admin panel for users in `dns-admins` group for resetting user zones.
