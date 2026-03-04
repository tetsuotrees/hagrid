# ADR-007: MCP Naming and Transport

## Status

Accepted

## Context

Hagrid v0.3 plans to expose its index to AI assistants and other tools via
the Model Context Protocol (MCP). MCP requires tool definitions with
namespaced names and a transport mechanism for communication.

Key design questions:

- What namespace should Hagrid's MCP tools use?
- What transport should the MCP server use?
- Should MCP be enabled by default?

## Decision

### Namespace

All MCP tools exposed by Hagrid use the `hagrid_` prefix:

- `hagrid_search` -- search references by path, label, or fingerprint prefix.
- `hagrid_drift` -- check drift status for a group or all groups.
- `hagrid_group_list` -- list confirmed groups.
- `hagrid_ref_info` -- get detail for a specific reference.

The underscore naming follows MCP conventions (snake_case tool names). The
`hagrid_` prefix avoids collisions with other MCP servers.

### Transport

The MCP server communicates via a Unix domain socket at:

```
~/.hagrid/hagrid.sock
```

Unix sockets were chosen over TCP because:

- No port conflicts or firewall considerations.
- File-permission-based access control (socket file is owned by the user).
- No network exposure -- the socket is local-only by construction.

The socket file is created when the MCP server starts and removed on clean
shutdown. Stale socket files (from crashes) are detected and cleaned up on
the next start.

### Opt-in

MCP support requires explicit opt-in. It is not started during normal CLI
operations. To enable:

```bash
hagrid mcp start    # Start the MCP server (foreground)
hagrid mcp start -d # Start as a background daemon
```

No MCP code runs unless the user explicitly starts the server.

## Consequences

- The `hagrid_` namespace is simple and unlikely to collide. If Hagrid is
  ever used alongside another `hagrid_`-prefixed MCP server (unlikely), the
  prefix can be made configurable.
- Unix socket transport limits MCP to the local machine, which aligns with
  Hagrid's single-machine trust model.
- Explicit opt-in means MCP adds zero attack surface for users who don't
  need it. The MCP module can be feature-gated at compile time if needed.
- The socket path is fixed (`~/.hagrid/hagrid.sock`), which simplifies MCP
  client configuration. Clients only need to know the socket path, not a
  host and port.
