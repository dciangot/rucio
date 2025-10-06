# Dockerfile for Rucio MCP Server
# Compatible with Docker MCP Gateway

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code
COPY server.py .

# Add metadata label for Docker MCP Gateway
LABEL io.docker.server.metadata='{ \
  "name": "rucio-mcp-server", \
  "description": "MCP Server for Rucio Data Management - provides tools to interact with Rucio for managing scientific data across distributed storage", \
  "command": ["python", "/app/server.py"], \
  "env": [ \
    { \
      "name": "RUCIO_HOST", \
      "value": "{{rucio-mcp-server.rucio-host}}" \
    }, \
    { \
      "name": "RUCIO_AUTH_HOST", \
      "value": "{{rucio-mcp-server.rucio-auth-host}}" \
    }, \
    { \
      "name": "RUCIO_ACCOUNT", \
      "value": "{{rucio-mcp-server.rucio-account}}" \
    }, \
    { \
      "name": "RUCIO_AUTH_TYPE", \
      "value": "{{rucio-mcp-server.rucio-auth-type}}" \
    } \
  ], \
  "secrets": [ \
    { \
      "name": "rucio-mcp-server.RUCIO_USERNAME", \
      "env": "RUCIO_USERNAME" \
    }, \
    { \
      "name": "rucio-mcp-server.RUCIO_PASSWORD", \
      "env": "RUCIO_PASSWORD" \
    } \
  ], \
  "config": [ \
    { \
      "name": "rucio-mcp-server", \
      "type": "object", \
      "properties": { \
        "rucio-host": { \
          "type": "string", \
          "description": "Rucio server URL (e.g., https://rucio-server.example.com)", \
          "default": "" \
        }, \
        "rucio-auth-host": { \
          "type": "string", \
          "description": "Rucio authentication server URL (e.g., https://rucio-auth.example.com)", \
          "default": "" \
        }, \
        "rucio-account": { \
          "type": "string", \
          "description": "Rucio account name", \
          "default": "root" \
        }, \
        "rucio-auth-type": { \
          "type": "string", \
          "description": "Authentication type (userpass, x509, oidc, etc.)", \
          "default": "userpass", \
          "enum": ["userpass", "x509", "oidc", "gss", "ssh", "saml"] \
        } \
      }, \
      "required": ["rucio-host", "rucio-auth-host", "rucio-account"] \
    } \
  ] \
}'

# Run the server
CMD ["python", "/app/server.py"]
