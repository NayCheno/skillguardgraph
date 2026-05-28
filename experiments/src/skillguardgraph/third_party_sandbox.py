"""Curated third-party public-code fixtures for sandbox execution.

These fixtures are copied from public third-party package documentation or
source files and executed only inside the local sandbox harness. They are not
fetched or executed from remote origins at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ThirdPartyFixture:
    fixture_id: str
    label: str
    source_url: str
    description: str
    source_code: str
    invoke: str


def build_third_party_fixtures() -> List[ThirdPartyFixture]:
    return [
        ThirdPartyFixture(
            fixture_id="mcp-sdk-quickstart",
            label="benign_registration",
            source_url="https://pypi.org/project/mcp/",
            description="Official MCP Python SDK quickstart server snippet.",
            source_code=(
                'from mcp.server.fastmcp import FastMCP\n\n'
                'mcp = FastMCP("Demo", json_response=True)\n\n'
                '@mcp.tool()\n'
                'def add(a: int, b: int) -> int:\n'
                '    """Add two numbers"""\n'
                '    return a + b\n\n'
                '@mcp.resource("greeting://{name}")\n'
                'def get_greeting(name: str) -> str:\n'
                '    """Get a personalized greeting"""\n'
                '    return f"Hello, {name}!"\n\n'
                '@mcp.prompt()\n'
                'def greet_user(name: str, style: str = "friendly") -> str:\n'
                '    """Generate a greeting prompt"""\n'
                '    return name\n'
            ),
            invoke="result = {'tool_count': len(mcp._tools), 'resource_count': len(mcp._resources), 'prompt_count': len(mcp._prompts)}",
        ),
        ThirdPartyFixture(
            fixture_id="fastmcp-quickstart",
            label="benign_registration",
            source_url="https://pypi.org/project/fastmcp/",
            description="FastMCP quickstart server snippet.",
            source_code=(
                'from fastmcp import FastMCP\n\n'
                'mcp = FastMCP("Demo")\n\n'
                '@mcp.tool\n'
                'def add(a: int, b: int) -> int:\n'
                '    """Add two numbers"""\n'
                '    return a + b\n'
            ),
            invoke="result = {'tool_count': len(mcp._tools), 'server_name': mcp.name}",
        ),
        ThirdPartyFixture(
            fixture_id="mcp-clipboard-subprocess",
            label="subprocess_behavior",
            source_url="https://github.com/cmeans/mcp-clipboard/blob/main/src/mcp_clipboard/clipboard.py",
            description="mcp-clipboard subprocess write helper excerpt.",
            source_code=(
                'import asyncio\n\n'
                'class ClipboardError(Exception):\n'
                '    pass\n\n'
                'async def _run_with_stdin(cmd: list[str], input_data: bytes, *, timeout: float = 5.0, env: dict[str, str] | None = None) -> None:\n'
                '    debug = False\n'
                '    stderr_mode = asyncio.subprocess.DEVNULL\n'
                '    proc = await asyncio.create_subprocess_exec(\n'
                '        *cmd,\n'
                '        stdin=asyncio.subprocess.PIPE,\n'
                '        stdout=asyncio.subprocess.DEVNULL,\n'
                '        stderr=stderr_mode,\n'
                '        env=env,\n'
                '    )\n'
                '    _, stderr_data = await asyncio.wait_for(proc.communicate(input=input_data), timeout=timeout)\n'
                '    if proc.returncode != 0:\n'
                '        msg = f"Clipboard write failed (rc={proc.returncode}): {cmd[0]}"\n'
                '        if debug and stderr_data:\n'
                '            msg += f"\\nstderr: {stderr_data.decode(errors=\'replace\').strip()}"\n'
                '        raise ClipboardError(msg)\n'
            ),
            invoke="import asyncio\nasync def _fixture_call():\n    await _run_with_stdin(['wl-copy', '--type', 'text/plain'], b'test-data')\nasyncio.run(_fixture_call())\nresult = {'subprocess_invoked': True}",
        ),
    ]
