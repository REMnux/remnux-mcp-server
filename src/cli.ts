#!/usr/bin/env node

import { startServer, type ServerConfig } from "./index.js";

function parseArgs(): ServerConfig {
  const args = process.argv.slice(2);
  const config: ServerConfig = {
    mode: "local",
    samplesDir: "/home/remnux/files/samples",
    outputDir: "/home/remnux/files/output",
    timeout: 300,
    noSandbox: true,
  };

  for (let i = 0; i < args.length; i++) {
    let arg = args[i];
    let value = args[i + 1];
    let usedEqualsSyntax = false;

    // Support --flag=value syntax: split on first '='
    if (arg.startsWith("--") && arg.includes("=")) {
      const eqIndex = arg.indexOf("=");
      value = arg.slice(eqIndex + 1);
      arg = arg.slice(0, eqIndex);
      usedEqualsSyntax = true;
    }

    // Helper: only skip next arg if value came from separate arg (not '=' syntax)
    const consumeValue = () => { if (!usedEqualsSyntax) i++; };

    switch (arg) {
      case "--mode":
        if (value === "docker" || value === "ssh" || value === "local") {
          config.mode = value;
        }
        consumeValue();
        break;
      case "--container":
        config.container = value;
        consumeValue();
        break;
      case "--host":
        config.host = value;
        consumeValue();
        break;
      case "--user":
        config.user = value;
        consumeValue();
        break;
      case "--port":
        config.port = parseInt(value, 10);
        consumeValue();
        break;
      case "--password":
        config.password = value;
        consumeValue();
        break;
      case "--samples-dir":
        config.samplesDir = value;
        consumeValue();
        break;
      case "--output-dir":
        config.outputDir = value;
        consumeValue();
        break;
      case "--timeout":
        config.timeout = parseInt(value, 10);
        consumeValue();
        break;
      case "--sandbox":
        config.noSandbox = false;
        break;
      case "--no-sandbox":
        // Backwards compatibility — already the default
        break;
      case "--transport":
        if (value === "stdio" || value === "http") {
          config.transport = value;
        }
        consumeValue();
        break;
      case "--http-port":
        config.httpPort = parseInt(value, 10);
        consumeValue();
        break;
      case "--http-host":
        config.httpHost = value;
        consumeValue();
        break;
      case "--http-token":
        config.httpToken = value;
        consumeValue();
        break;
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      case "--version":
      case "-v":
        console.log("@remnux/mcp-server v0.1.4");
        process.exit(0);
    }
  }

  // Read token from env var if not set via CLI
  if (!config.httpToken && process.env.MCP_TOKEN) {
    config.httpToken = process.env.MCP_TOKEN;
  }

  return config;
}

function printHelp() {
  console.log(`
@remnux/mcp-server - MCP server for using the REMnux malware analysis toolkit via AI assistants

USAGE:
  npx @remnux/mcp-server [OPTIONS]

OPTIONS:
  --mode <mode>           Connection mode: local, docker, or ssh (default: local)
  --container <name>      Docker container name/ID (for docker mode)
  --host <host>           SSH host (for ssh mode)
  --user <user>           SSH user (default: remnux)
  --port <port>           SSH port (default: 22)
  --password <pass>       SSH password (uses SSH agent if omitted)
  --samples-dir <path>    Path to samples directory (default: /home/remnux/files/samples)
  --output-dir <path>     Path to output directory (default: /home/remnux/files/output)
  --timeout <seconds>     Default command timeout (default: 300)
  --sandbox               Enable path sandboxing (restrict files to samples/output dirs)
  --no-sandbox            No-op (sandbox is already off by default)
  --transport <mode>      Transport: stdio (default) or http
  --http-port <port>      HTTP port (default: 3000)
  --http-host <host>      HTTP bind address (default: 127.0.0.1)
  --http-token <token>    Bearer token for HTTP auth (also reads MCP_TOKEN env var)
  -h, --help              Show this help message
  -v, --version           Show version

EXAMPLES:
  # Local mode (default — run directly on REMnux)
  npx @remnux/mcp-server

  # Docker mode (REMnux in a container)
  npx @remnux/mcp-server --mode=docker --container=remnux

  # SSH mode (remote REMnux host)
  npx @remnux/mcp-server --mode=ssh --host=192.168.1.100 --user=remnux

  # HTTP transport (server inside REMnux)
  npx @remnux/mcp-server --transport=http --http-token=SECRET

  # Add to Claude Code (stdio)
  claude mcp add remnux -- npx @remnux/mcp-server

For tool discovery and documentation, use the REMnux docs MCP:
  https://docs.remnux.org/~gitbook/mcp
`);
}

// Start server
startServer(parseArgs()).catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
