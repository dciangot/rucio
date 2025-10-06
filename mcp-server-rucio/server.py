#!/usr/bin/env python3
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Rucio MCP Server

This MCP (Model Context Protocol) server provides programmatic access to Rucio
data management capabilities through standardized tool interfaces.
"""

import asyncio
import json
import logging
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Import Rucio client
try:
    from rucio.client import Client
    from rucio.common.exception import (
        RucioException,
        DataIdentifierNotFound,
        ReplicaNotFound,
        RSENotFound,
        RuleNotFound,
        AccountNotFound,
    )
except ImportError:
    raise ImportError(
        "Rucio client not found. Please install rucio-clients: pip install rucio-clients"
    )

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("rucio-mcp-server")

# Initialize MCP server
app = Server("rucio-mcp-server")

# Global Rucio client instance
rucio_client: Client | None = None


def get_rucio_client() -> Client:
    """Get or create Rucio client instance."""
    global rucio_client
    if rucio_client is None:
        # Initialize client with config or environment variables
        # Supports standard Rucio configuration methods
        rucio_client = Client()
        logger.info("Rucio client initialized")
    return rucio_client


def format_result(data: Any) -> str:
    """Format result as JSON string."""
    if isinstance(data, (list, dict)):
        return json.dumps(data, indent=2, default=str)
    return str(data)


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available Rucio MCP tools."""
    return [
        # DID Operations
        Tool(
            name="rucio_list_dids",
            description="List data identifiers (DIDs) in a scope with optional filters. "
            "Returns files, datasets, or containers matching the specified criteria.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "description": "Scope name (e.g., 'test', 'user.jdoe')"},
                    "filters": {
                        "type": "array",
                        "description": "Filters as list of dicts. Example: [{'name': 'data*'}] or [{'created_after': '2024-01-01'}]",
                        "items": {"type": "object"},
                        "default": [{}],
                    },
                    "did_type": {
                        "type": "string",
                        "enum": ["all", "collection", "dataset", "container", "file"],
                        "default": "collection",
                        "description": "Type of DID to list",
                    },
                    "long": {"type": "boolean", "default": False, "description": "Include detailed information"},
                },
                "required": ["scope"],
            },
        ),
        Tool(
            name="rucio_get_did",
            description="Get metadata for a specific data identifier (DID).",
            inputSchema={
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "description": "Scope name"},
                    "name": {"type": "string", "description": "DID name"},
                },
                "required": ["scope", "name"],
            },
        ),
        Tool(
            name="rucio_list_did_contents",
            description="List contents of a dataset or container (what files/datasets it contains).",
            inputSchema={
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "description": "Scope name"},
                    "name": {"type": "string", "description": "DID name"},
                },
                "required": ["scope", "name"],
            },
        ),
        # Replica Operations
        Tool(
            name="rucio_list_replicas",
            description="List all physical replicas (locations) of one or more DIDs. "
            "Shows where data is physically stored across RSEs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dids": {
                        "type": "array",
                        "description": "List of DIDs as [{'scope': 'test', 'name': 'file1'}, ...]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "scope": {"type": "string"},
                                "name": {"type": "string"},
                            },
                            "required": ["scope", "name"],
                        },
                    },
                    "rse_expression": {
                        "type": "string",
                        "description": "Filter replicas by RSE expression (optional)",
                    },
                },
                "required": ["dids"],
            },
        ),
        # RSE Operations
        Tool(
            name="rucio_list_rses",
            description="List Rucio Storage Elements (RSEs) matching an expression. "
            "RSEs represent physical storage locations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rse_expression": {
                        "type": "string",
                        "description": "RSE expression (e.g., 'tier=1', 'CERN-*', 'type=DISK')",
                        "default": "",
                    },
                },
            },
        ),
        Tool(
            name="rucio_get_rse",
            description="Get detailed information about a specific RSE including attributes and protocols.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rse": {"type": "string", "description": "RSE name"},
                },
                "required": ["rse"],
            },
        ),
        Tool(
            name="rucio_get_rse_usage",
            description="Get storage usage information for an RSE (used/free space).",
            inputSchema={
                "type": "object",
                "properties": {
                    "rse": {"type": "string", "description": "RSE name"},
                },
                "required": ["rse"],
            },
        ),
        # Rule Operations
        Tool(
            name="rucio_list_rules",
            description="List replication rules. Rules define data placement policies. "
            "Can filter by account, DID, or rule state.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filters": {
                        "type": "object",
                        "description": "Filter dict (e.g., {'account': 'root', 'state': 'OK'})",
                        "default": {},
                    },
                },
            },
        ),
        Tool(
            name="rucio_get_rule",
            description="Get detailed information about a specific replication rule.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "Rule ID (UUID)"},
                },
                "required": ["rule_id"],
            },
        ),
        Tool(
            name="rucio_add_rule",
            description="Create a new replication rule to replicate data to RSE(s). "
            "This triggers data transfers to ensure N copies exist at specified locations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "dids": {
                        "type": "array",
                        "description": "List of DIDs to replicate",
                        "items": {
                            "type": "object",
                            "properties": {
                                "scope": {"type": "string"},
                                "name": {"type": "string"},
                            },
                            "required": ["scope", "name"],
                        },
                    },
                    "copies": {
                        "type": "integer",
                        "description": "Number of copies to create",
                        "default": 1,
                    },
                    "rse_expression": {
                        "type": "string",
                        "description": "Target RSE expression (e.g., 'CERN-PROD')",
                    },
                    "lifetime": {
                        "type": "integer",
                        "description": "Rule lifetime in seconds (optional, null for infinite)",
                    },
                    "comment": {
                        "type": "string",
                        "description": "Comment for the rule",
                    },
                },
                "required": ["dids", "copies", "rse_expression"],
            },
        ),
        # Account Operations
        Tool(
            name="rucio_whoami",
            description="Get information about the current authenticated account.",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="rucio_get_account_usage",
            description="Get storage usage and quota information for an account on RSEs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "account": {"type": "string", "description": "Account name"},
                    "rse_expression": {
                        "type": "string",
                        "description": "Filter by RSE expression (optional)",
                    },
                },
                "required": ["account"],
            },
        ),
        # Scope Operations
        Tool(
            name="rucio_list_scopes",
            description="List all available scopes. Scopes are top-level namespaces for organizing data.",
            inputSchema={"type": "object", "properties": {}},
        ),
        # Request/Transfer Operations
        Tool(
            name="rucio_list_requests",
            description="List data transfer requests with their states. Shows pending/ongoing/failed transfers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "src_rse": {"type": "string", "description": "Source RSE (optional)"},
                    "dst_rse": {"type": "string", "description": "Destination RSE (optional)"},
                    "request_states": {
                        "type": "array",
                        "description": "Filter by states: ['QUEUED', 'SUBMITTED', 'FAILED', 'DONE', 'LOST']",
                        "items": {"type": "string"},
                    },
                },
            },
        ),
        # Ping/Health
        Tool(
            name="rucio_ping",
            description="Check connection to Rucio server and get server version information.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls."""
    try:
        client = get_rucio_client()
        result = None

        # DID Operations
        if name == "rucio_list_dids":
            scope = arguments["scope"]
            filters = arguments.get("filters", [{}])
            did_type = arguments.get("did_type", "collection")
            long_format = arguments.get("long", False)

            dids = list(
                client.list_dids(
                    scope=scope,
                    filters=filters,
                    did_type=did_type,
                    long=long_format,
                )
            )
            result = {"count": len(dids), "dids": dids}

        elif name == "rucio_get_did":
            scope = arguments["scope"]
            name_arg = arguments["name"]
            did_info = client.get_did(scope=scope, name=name_arg)
            result = did_info

        elif name == "rucio_list_did_contents":
            scope = arguments["scope"]
            name_arg = arguments["name"]
            contents = list(client.list_content(scope=scope, name=name_arg))
            result = {"count": len(contents), "contents": contents}

        # Replica Operations
        elif name == "rucio_list_replicas":
            dids = arguments["dids"]
            rse_expression = arguments.get("rse_expression")

            replicas = list(
                client.list_replicas(
                    dids=dids,
                    rse_expression=rse_expression,
                )
            )
            result = {"count": len(replicas), "replicas": replicas}

        # RSE Operations
        elif name == "rucio_list_rses":
            rse_expression = arguments.get("rse_expression", "")
            rses = list(client.list_rses(rse_expression=rse_expression))
            result = {"count": len(rses), "rses": rses}

        elif name == "rucio_get_rse":
            rse = arguments["rse"]
            rse_info = client.get_rse(rse=rse)
            result = rse_info

        elif name == "rucio_get_rse_usage":
            rse = arguments["rse"]
            usage = list(client.get_rse_usage(rse=rse))
            result = {"rse": rse, "usage": usage}

        # Rule Operations
        elif name == "rucio_list_rules":
            filters = arguments.get("filters", {})
            rules = list(client.list_replication_rules(filters=filters))
            result = {"count": len(rules), "rules": rules}

        elif name == "rucio_get_rule":
            rule_id = arguments["rule_id"]
            rule_info = client.get_replication_rule(rule_id=rule_id)
            result = rule_info

        elif name == "rucio_add_rule":
            dids = arguments["dids"]
            copies = arguments["copies"]
            rse_expression = arguments["rse_expression"]
            lifetime = arguments.get("lifetime")
            comment = arguments.get("comment")

            rule_ids = client.add_replication_rule(
                dids=dids,
                copies=copies,
                rse_expression=rse_expression,
                lifetime=lifetime,
                comment=comment,
            )
            result = {"rule_ids": rule_ids}

        # Account Operations
        elif name == "rucio_whoami":
            info = client.whoami()
            result = info

        elif name == "rucio_get_account_usage":
            account = arguments["account"]
            rse_expression = arguments.get("rse_expression")
            usage = list(
                client.get_local_account_usage(
                    account=account,
                    rse_expression=rse_expression,
                )
            )
            result = {"account": account, "usage": usage}

        # Scope Operations
        elif name == "rucio_list_scopes":
            scopes = list(client.list_scopes())
            result = {"count": len(scopes), "scopes": scopes}

        # Request Operations
        elif name == "rucio_list_requests":
            src_rse = arguments.get("src_rse")
            dst_rse = arguments.get("dst_rse")
            request_states = arguments.get("request_states")

            requests = list(
                client.list_requests(
                    src_rse=src_rse,
                    dst_rse=dst_rse,
                    request_states=request_states,
                )
            )
            result = {"count": len(requests), "requests": requests}

        # Ping
        elif name == "rucio_ping":
            ping_result = client.ping()
            result = ping_result

        else:
            return [
                TextContent(
                    type="text",
                    text=f"Unknown tool: {name}",
                )
            ]

        # Format and return result
        return [
            TextContent(
                type="text",
                text=format_result(result),
            )
        ]

    except DataIdentifierNotFound as e:
        return [TextContent(type="text", text=f"DID not found: {str(e)}")]
    except ReplicaNotFound as e:
        return [TextContent(type="text", text=f"Replica not found: {str(e)}")]
    except RSENotFound as e:
        return [TextContent(type="text", text=f"RSE not found: {str(e)}")]
    except RuleNotFound as e:
        return [TextContent(type="text", text=f"Rule not found: {str(e)}")]
    except AccountNotFound as e:
        return [TextContent(type="text", text=f"Account not found: {str(e)}")]
    except RucioException as e:
        return [TextContent(type="text", text=f"Rucio error: {str(e)}")]
    except Exception as e:
        logger.error(f"Error calling tool {name}: {str(e)}", exc_info=True)
        return [
            TextContent(
                type="text",
                text=f"Error: {str(e)}",
            )
        ]


async def main():
    """Run the MCP server."""
    logger.info("Starting Rucio MCP Server")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
