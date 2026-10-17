try:
    from mcp.server import MCPServer as Server  # newer SDK name
except ImportError:
    from mcp.server.fastmcp import FastMCP as Server  # older SDK name

server = Server("hello")


@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    server.run()
