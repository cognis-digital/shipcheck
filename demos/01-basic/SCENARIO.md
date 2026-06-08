# Demo 01 - basic Dockerfile lint

This demo lints a realistic but flawed Node.js `Dockerfile` that exhibits
several common ship-blocking problems SHIPCHECK detects.

## Input

`Dockerfile` in this directory:

```dockerfile
FROM node:12
ADD . /app
WORKDIR /app
RUN apt-get update
RUN apt-get install -y curl git
RUN curl https://install.example.com/tool.sh | sh
RUN npm install
ENV API_KEY=sk_live_abcdef123456
EXPOSE 22
CMD ["node", "server.js"]
```

## Run it

```bash
python -m shipcheck lint demos/01-basic/Dockerfile
python -m shipcheck lint demos/01-basic/Dockerfile --format json
```

## What SHIPCHECK flags

| Code  | Severity | Why |
|-------|----------|-----|
| SC120 | critical | `node:12` is end-of-life (offline advisory table) |
| SC110 | info     | `node` is a heavy base; use `-slim`/`-alpine` |
| SC240 | low      | `ADD . /app` should be `COPY` |
| SC250 | info     | copying the whole context early kills layer caching |
| SC201 | high     | `apt-get update` in its own layer -> stale cache |
| SC202/203 | low  | missing `--no-install-recommends` + cache cleanup |
| SC221 | high     | `curl ... | sh` remote-exec |
| SC260 | medium   | `EXPOSE 22` (sshd in a container) |
| SC300 | high     | never drops from root (no `USER`) |

`ENV API_KEY=...` is intentionally a secret-shaped value; the secret rule
fires inside `RUN` layers (where it persists), which this demo also exercises
via the size/cache rules.

The command exits non-zero because findings reach the `--fail-on medium`
threshold.
