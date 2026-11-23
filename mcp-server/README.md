# mcp-server/ — OpenCobot MCP server

MCP (Model Context Protocol) interface. Exposes OpenCobot tools to
MCP-compatible clients. See [ARCHITECTURE.md §2](../ARCHITECTURE.md).

## Run

Stdio transport, JSON-RPC 2.0, line-delimited JSON (a JSON array on one
line is treated as a batch). The directory name is hyphenated, so this
is a script, not a package — run it directly:

```bash
python mcp-server/server.py --state-dir ~/.opencobot
# state dir default: $OPENCOBOT_STATE or ~/.opencobot
```

Nothing is printed to stdout except JSON-RPC responses; diagnostics go
to stderr.

## Methods

| Method | Result |
| ------ | ------ |
| `initialize` | `{protocolVersion: "2024-11-05", capabilities: {tools: {}}, serverInfo: {name: "opencobot", version: "0.1.0"}}` |
| `ping` | `{}` |
| `tools/list` | `{tools: [{name, description, inputSchema}]}` from the tool registry |
| `tools/call` | `{content: [{type: "text", text: "<result JSON>"}], isError: bool}` |
| `notifications/initialized` | no reply (any `notifications/*` gets no reply) |

Unknown methods return JSON-RPC error `-32601`; malformed JSON returns
`-32700`.

## How `tools/call` works

Each call issues a short-lived (600s) capability token scoped to the
working directory (plus any paths named in `arguments`), for that one
tool only, then runs it through the runtime with the policy engine.
Level 3+ tools need an explicit approval; without one the call returns
`isError: true` with a `needs approval` message and nothing executes.

> **Standalone-mode note:** this server uses the policy engine
> in-process (`policy.engine.PolicyEngine`), backed by the shared
> state dir and audit log. That is weaker isolation than the
> separate `policyd` process the daemon/CLI path uses, and if the
> real policy engine is not installed the server fails loudly
> instead of running a weaker copy (R-009: the old
> `cli/_fallback.py` was deleted). When `policyd` (or the daemon)
> is running, the daemon path should be preferred; a future version
> of this server will route `tools/call` through the daemon socket
> instead.

## Example client config

Claude Desktop (`claude_desktop_config.json` — adjust the paths to
your checkout):

```json
{
  "mcpServers": {
    "opencobot": {
      "command": "/usr/bin/python3",
      "args": ["/home/you/opencobot/mcp-server/server.py",
               "--state-dir", "/home/you/.opencobot"],
      "env": {}
    }
  }
}
```

MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python3 mcp-server/server.py --state-dir ~/.opencobot
```

## Smoke test (manual)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_dir","arguments":{"path":"/tmp"}}}' \
  | python mcp-server/server.py --state-dir /tmp/oc-test-state
```
