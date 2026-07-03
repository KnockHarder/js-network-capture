# Network Capture Hook — Design Spec

**Date:** 2026-07-03
**Status:** Approved

## Overview

A Node.js preload hook (`--require`) that intercepts all HTTP/HTTPS requests made by
an application and writes structured capture files to `$HOME/.networkLogs/`.

## Architecture

```
node --require ./hook.js app
```

`hook.js` monkey-patches `http.request`, `http.get`, `https.request`, `https.get`,
and `globalThis.fetch` (when available) so every outbound request passes through the
recorder without the application being aware of it.

```
hook.js
├── patcher.js       — monkey-patch http/https/fetch
├── recorder.js      — file I/O for capture directories
├── sanitizer.js     — redact sensitive fields from headers/params/bodies
├── numbering.js     — 001–999 rotating directory numbering
└── brief.js         — generate structural preview for large JSON bodies
```

## Directory Layout

Each request creates a subdirectory under `$HOME/.networkLogs/`:

```
~/.networkLogs/
└── 001-httpbin.org-post/
    ├── request_header.prop       # key: value, one per line (redacted)
    ├── request_params.prop       # URL query string params (redacted)
    ├── request_body.json         # formatted JSON (when body parses as JSON)
    ├── request_body.brief.json   # structural preview of request_body.json
    ├── request_body.txt          # raw body when NOT JSON
    ├── response_header.prop      # key: value, one per line
    ├── response.json             # formatted JSON (when body parses as JSON)
    ├── response.brief.json       # structural preview of response.json
    ├── response.txt              # raw body when NOT JSON
    ├── stream.txt                # per-chunk timestamps (request + response)
    ├── path_info.txt             # full un-truncated path (only when name was cut)
    └── error.txt                 # error message + stack (only on failure)
```

### Directory Naming

Format: `{NNN}-{hostname}-{path-segments}`

- `NNN` — 3-digit zero-padded sequence (001–999, wraps to 001 after 999).
- `hostname` — the request's host (domain or IP).
- `path-segments` — the URL path with `/` replaced by `-`, query string stripped.
- Total name capped at 150 chars; excess path segments are truncated.
- When truncated, the full original path is written to `path_info.txt` inside the
  directory.

### Numbering (numbering.js)

On startup, scan `~/.networkLogs/` to find the highest existing sequence number.
Start from `max + 1`. When the counter reaches 1000 it wraps to 001, silently
replacing the old directory.

Thread safety: Node's single-threaded event loop guarantees that only one request
is processed at a time during the synchronous part of directory creation. All file
writes are streamed asynchronously and are independent per request.

## File Formats

### `.prop` files (request_header.prop, request_params.prop, response_header.prop)

One entry per line:

```
Content-Type: application/json
Authorization: ***REDACTED***
```

Values are redacted before writing (see Redaction).

### `.json` files (request_body.json, response.json)

Pretty-printed JSON with 2-space indent. Written after the entire body has been
buffered in memory.

### `.brief.json` files

Structural preview of the corresponding `.json` file:
- Strings longer than 50 chars → truncated to 50 + `"... (N more chars)"`.
- Arrays longer than 6 items → keep first 3 and last 3, middle replaced with
  `"... (N more items)"`.
- Objects keep all keys but values follow the same truncation rules.
- Depth is preserved as-is.

### `.txt` files (request_body.txt, response.txt)

Raw body written verbatim. Used when `Content-Type` is not JSON or when the body
does not parse as valid JSON.

### stream.txt

One line per chunk, two possible prefixes:

```
[2026-07-03T12:34:56.789Z] [request]  256 bytes
[2026-07-03T12:34:56.890Z] [response] 1024 bytes
```

Written immediately (appended) as each chunk arrives — not buffered.

### error.txt

Written only when a request fails (socket error, timeout, DNS failure):

```
Error: connect ECONNREFUSED 127.0.0.1:8080
    at ...
```

### path_info.txt

Written only when the directory name was truncated. Contains the original full URL
path.

## Redaction (sanitizer.js)

Before any data is written to disk, sensitive fields are replaced with
`***REDACTED***`.

**Trigger keywords** (case-insensitive substring match on the key name):

```
token, password, pass, secret, api_key, apikey, api-key,
auth, authorization, credential, access_key, accesskey,
private_key, pwd, passwd, bearer, refresh_token
```

**Redacted locations:**
- Request headers (keys and values)
- URL query parameters (keys and values)
- Request body (keys and values, only when the body is JSON)

## Request Lifecycle

```
1. App calls http.request(options)
2. Patcher intercepts → assigns sequence number → creates directory
3. Writes request_header.prop and request_params.prop immediately
4. Streams request chunks → appends to stream.txt, buffers in memory
5. On request 'end' → writes request_body.json (or .txt + .brief)
6. Streams response chunks → appends to stream.txt, buffers in memory
7. On response 'end' → writes response_header.prop, response.json (or .txt + .brief)
8. On error → writes error.txt, preserves already-written files
```

## Error Handling

- The hook must **never throw** into the application. All internal errors are caught
  and logged to stderr (development only, controlled by `NETWORK_CAPTURE_DEBUG=1`).
- File system errors (disk full, permission denied) are caught and silently ignored
  so the application continues normally.

## Disabling

Set `NETWORK_CAPTURE=off` before launching the application. The hook loads but
returns immediately without patching anything.

Set `NETWORK_CAPTURE_DEBUG=1` to enable verbose error logging to stderr.

## Usage

```bash
# Capture all requests
node --require ./path/to/js-network-capture/hook.js app.js

# Disable at runtime
NETWORK_CAPTURE=off node --require ./path/to/js-network-capture/hook.js app.js

# Debug mode
NETWORK_CAPTURE_DEBUG=1 node --require ./path/to/js-network-capture/hook.js app.js
```

## Scope / Non-Goals

- **In scope:** HTTP/HTTPS requests made through `http`, `https`, and `globalThis.fetch`.
- **Out of scope:** HTTP/2 direct connections, WebSocket frames, `net.Socket` raw
  connections, request replay/playback, a GUI viewer.

## Test Strategy

Unit tests for each module (sanitizer, numbering, brief) plus an integration test
that starts a small HTTP server, fires requests against it, and verifies the
captured directory contents.