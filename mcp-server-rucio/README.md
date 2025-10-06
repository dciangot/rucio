# Rucio MCP Server

An MCP (Model Context Protocol) server that provides programmatic access to Rucio data management capabilities through standardized tool interfaces.

## Overview

This MCP server exposes Rucio client functionality as tools that can be used by MCP clients (like Claude Desktop, IDEs, or custom applications) to interact with Rucio data management systems.

## Features

The server provides tools for:

- **DID Operations**: List, query, and manage Data Identifiers (files, datasets, containers)
- **Replica Management**: List and query physical file replicas across storage systems
- **RSE Operations**: Query Rucio Storage Elements and their usage statistics
- **Replication Rules**: Create and manage data placement policies
- **Account Management**: Check account information and quotas
- **Transfer Monitoring**: Track data transfer requests and their states
- **Health Checks**: Verify server connectivity

## Installation

### Prerequisites

- Python 3.9 or higher
- Rucio client configuration (see Configuration section)

### Install from source

```bash
cd mcp-server-rucio
pip install -e .
```

### Install dependencies only

```bash
pip install mcp rucio-clients
```

## Configuration

The server uses standard Rucio client configuration. Configure Rucio using one of these methods:

### 1. Configuration File

Create or edit `~/.rucio/rucio.cfg`:

```ini
[client]
rucio_host = https://rucio-server.example.com
auth_host = https://rucio-auth.example.com
auth_type = userpass
account = myaccount
username = myusername
password = mypassword
ca_cert = /etc/grid-security/certificates
```

### 2. Environment Variables

```bash
export RUCIO_HOST=https://rucio-server.example.com
export RUCIO_AUTH_HOST=https://rucio-auth.example.com
export RUCIO_ACCOUNT=myaccount
export RUCIO_AUTH_TYPE=userpass
export RUCIO_USERNAME=myusername
export RUCIO_PASSWORD=mypassword
```

### 3. X.509 Certificate Authentication

```ini
[client]
rucio_host = https://rucio-server.example.com
auth_host = https://rucio-auth.example.com
auth_type = x509
account = myaccount
client_cert = /path/to/usercert.pem
client_key = /path/to/userkey.pem
ca_cert = /etc/grid-security/certificates
```

## Usage

### Method 1: Using Docker MCP Gateway (Recommended)

The Rucio MCP Server is compatible with [Docker MCP Gateway](https://github.com/docker/mcp-gateway), which simplifies deployment and configuration.

#### Build the Docker Image

```bash
cd mcp-server-rucio
docker build -t rucio-mcp-server:latest .
```

#### Run with Docker MCP Gateway

```bash
docker mcp gateway run --servers docker://rucio-mcp-server:latest
```

#### Configure the Server

When running via Docker MCP Gateway, configure the server using environment variables and secrets:

```bash
# Set configuration
docker mcp gateway config set rucio-mcp-server.rucio-host "https://rucio-server.example.com"
docker mcp gateway config set rucio-mcp-server.rucio-auth-host "https://rucio-auth.example.com"
docker mcp gateway config set rucio-mcp-server.rucio-account "myaccount"
docker mcp gateway config set rucio-mcp-server.rucio-auth-type "userpass"

# Set secrets
docker mcp gateway secret set rucio-mcp-server.RUCIO_USERNAME "myusername"
docker mcp gateway secret set rucio-mcp-server.RUCIO_PASSWORD "mypassword"
```

#### Publish to Registry (Optional)

To share with others or use across systems:

```bash
# Tag for your registry
docker tag rucio-mcp-server:latest myregistry/rucio-mcp-server:latest

# Push to registry
docker push myregistry/rucio-mcp-server:latest

# Use from registry
docker mcp gateway run --servers docker://myregistry/rucio-mcp-server:latest
```

### Method 2: Running Standalone

```bash
python server.py
```

The server communicates via stdin/stdout using the MCP protocol.

### Method 3: Using with Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "rucio": {
      "command": "python",
      "args": ["/path/to/rucio/mcp-server-rucio/server.py"]
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "rucio": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
        "-e", "RUCIO_HOST=https://rucio-server.example.com",
        "-e", "RUCIO_AUTH_HOST=https://rucio-auth.example.com",
        "-e", "RUCIO_ACCOUNT=myaccount",
        "-e", "RUCIO_USERNAME=myusername",
        "-e", "RUCIO_PASSWORD=mypassword",
        "rucio-mcp-server:latest"]
    }
  }
}
```

### Example Tool Calls

#### Check Server Connection

```json
{
  "name": "rucio_ping",
  "arguments": {}
}
```

#### List DIDs in a Scope

```json
{
  "name": "rucio_list_dids",
  "arguments": {
    "scope": "test",
    "filters": [{"name": "data*"}],
    "did_type": "file"
  }
}
```

#### List File Replicas

```json
{
  "name": "rucio_list_replicas",
  "arguments": {
    "dids": [
      {"scope": "test", "name": "file1"},
      {"scope": "test", "name": "file2"}
    ]
  }
}
```

#### Create Replication Rule

```json
{
  "name": "rucio_add_rule",
  "arguments": {
    "dids": [{"scope": "test", "name": "dataset1"}],
    "copies": 2,
    "rse_expression": "tier=1&disk=1",
    "comment": "Replicate important dataset"
  }
}
```

#### Check Account Usage

```json
{
  "name": "rucio_get_account_usage",
  "arguments": {
    "account": "myaccount",
    "rse_expression": "CERN-*"
  }
}
```

## Available Tools

### DID Operations

- `rucio_list_dids` - List data identifiers in a scope
- `rucio_get_did` - Get metadata for a specific DID
- `rucio_list_did_contents` - List contents of a dataset/container

### Replica Operations

- `rucio_list_replicas` - List physical replicas of DIDs

### RSE Operations

- `rucio_list_rses` - List storage elements
- `rucio_get_rse` - Get RSE details
- `rucio_get_rse_usage` - Get storage usage statistics

### Rule Operations

- `rucio_list_rules` - List replication rules
- `rucio_get_rule` - Get rule details
- `rucio_add_rule` - Create new replication rule

### Account Operations

- `rucio_whoami` - Get current account info
- `rucio_get_account_usage` - Get account usage and quotas

### Other Operations

- `rucio_list_scopes` - List all scopes
- `rucio_list_requests` - List transfer requests
- `rucio_ping` - Check server connection

## Development

### Running Tests

```bash
pip install -e ".[dev]"
pytest
```

### Code Formatting

```bash
black server.py
ruff check server.py
```

### Building and Testing Docker Image Locally

```bash
# Build
docker build -t rucio-mcp-server:dev .

# Test run
docker run -i --rm \
  -e RUCIO_HOST=https://rucio-server.example.com \
  -e RUCIO_AUTH_HOST=https://rucio-auth.example.com \
  -e RUCIO_ACCOUNT=myaccount \
  -e RUCIO_USERNAME=myusername \
  -e RUCIO_PASSWORD=mypassword \
  rucio-mcp-server:dev
```

## Docker MCP Gateway Integration

The Rucio MCP Server includes metadata for seamless integration with Docker MCP Gateway:

### Configuration Schema

- **rucio-host**: Rucio server URL
- **rucio-auth-host**: Rucio authentication server URL
- **rucio-account**: Account name
- **rucio-auth-type**: Authentication method (userpass, x509, oidc, gss, ssh, saml)

### Secrets

- **RUCIO_USERNAME**: Username for userpass authentication
- **RUCIO_PASSWORD**: Password for userpass authentication

### Using with Rucio Development Environment

If you're using the Rucio Docker development environment:

```bash
# Build the MCP server image
cd mcp-server-rucio
docker build -t rucio-mcp-server:latest .

# Run with Docker MCP Gateway pointing to dev environment
docker mcp gateway run --servers docker://rucio-mcp-server:latest

# Configure to use local Rucio dev server
docker mcp gateway config set rucio-mcp-server.rucio-host "http://rucio:80"
docker mcp gateway config set rucio-mcp-server.rucio-auth-host "http://rucio:80"
docker mcp gateway config set rucio-mcp-server.rucio-account "root"
docker mcp gateway secret set rucio-mcp-server.RUCIO_USERNAME "root"
docker mcp gateway secret set rucio-mcp-server.RUCIO_PASSWORD "secret"
```

## Troubleshooting

### Authentication Issues

If you see authentication errors:

1. Verify your Rucio configuration (environment variables or secrets)
2. Check that your account exists and has proper permissions
3. For x509 auth, ensure certificates are valid and not expired
4. Test with the standard Rucio CLI: `rucio whoami`

### Connection Issues

If the server cannot connect to Rucio:

1. Verify `RUCIO_HOST` and `RUCIO_AUTH_HOST` are correct
2. Check network connectivity
3. If using Docker, ensure containers can reach the Rucio server
4. Verify CA certificates are properly configured

### Docker MCP Gateway Issues

If tools aren't working with Docker MCP Gateway:

1. Check configuration: `docker mcp gateway config list`
2. Verify secrets are set: `docker mcp gateway secret list`
3. Check server logs: `docker mcp gateway logs`
4. Validate the image metadata: `docker inspect rucio-mcp-server:latest | grep io.docker.server.metadata`

### Tool Errors

If specific tools fail:

1. Check the tool arguments match the expected schema
2. Verify you have permissions for the requested operation
3. Check Rucio server logs for detailed error messages
4. Test the operation with the Rucio CLI to isolate the issue

## Contributing

Contributions are welcome! Please follow the main Rucio contribution guidelines at https://rucio.cern.ch/documentation/contributing

## License

Licensed under the Apache License, Version 2.0. See the main Rucio repository for details.

## Support

- Documentation: https://rucio.cern.ch/documentation
- Issues: https://github.com/rucio/rucio/issues
- Community: https://rucio.cern.ch/documentation/contact_us/
- Docker MCP Gateway: https://github.com/docker/mcp-gateway
