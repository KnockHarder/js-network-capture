# js-network-capture

Node.js network request interceptor — captures HTTP/HTTPS/fetch traffic to disk for debugging and auditing.

## Quick Start

```bash
# Start recording all HTTP/HTTPS/fetch requests
node --import ./hook.js your-app.js

# Or with --require (CommonJS)
node --require ./hook.js your-app.js

# Disable via env var
NETWORK_CAPTURE=off node --import ./hook.js your-app.js
```

## Output

Captured traffic is written to `~/.networkLogs/`, organized as:

```
~/.networkLogs/
└── <number>.<domain>.<truncated-path>/
    ├── request.json          # Method, URL, headers (sanitized), query params
    ├── request.bin           # Request body (if present, binary-safe)
    ├── response.json         # Status, headers (sanitized), brief body preview
    └── response.bin          # Response body (if not plain text)
```

## Sensitive Data

Headers matching these patterns are redacted as `***REDACTED***`:

- `authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`
- `refresh_token`, `private_key`, `access_token`, `secret`

## API

```js
const { patch } = require('js-network-capture/lib/patcher');
const logDir = '/path/to/output';

// Start patching
patch(logDir);
```

## Requirements

- Node.js >= 18.0.0

## License

MIT