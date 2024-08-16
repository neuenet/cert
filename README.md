# cert.neue

Creates `.crt` and `.key` certificate files for a supplied domain.

## Usage

API requires an object with `domain` and `ip`.

Generated files live in `certificates/<domain>` and the API will respond with an object containing `message` and `tlsa`.

API runs on port `2588`.

```sh
# using curl
curl -d '{ "domain": "www.lynk", "ip": "50.116.2.11" }' -H "Content-Type: application/json" -X POST http://localhost:2588/api
```

## Prerequisites

- unzip: `brew install unzip` or `apt install unzip -y`
- Deno: `curl -fsSL https://deno.land/install.sh | sh`
  - `export DENO_INSTALL="/root/.deno"`
  - `export PATH="$DENO_INSTALL/bin:$PATH"`

## Run

```sh
deno task start
```
