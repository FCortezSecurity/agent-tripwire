from pathlib import Path

from mcp.server import MCPServer

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = (ROOT / "sandbox").resolve()

server = MCPServer("files")


def _safe_path(relative: str) -> Path:
    """Resolve a path and refuse anything that leaves the sandbox."""
    candidate = (SANDBOX / relative).resolve()
    if not candidate.is_relative_to(SANDBOX):
        raise ValueError("path escapes the sandbox")
    return candidate


@server.tool()
def list_files(directory: str = ".") -> list[str]:
    """List files in a workspace directory."""
    base = _safe_path(directory)
    if not base.is_dir():
        raise ValueError("directory does not exist")
    return sorted(str(p.relative_to(SANDBOX)) for p in base.rglob("*") if p.is_file())


@server.tool()
def read_file(path: str) -> str:
    """Read a text file from the workspace."""
    return _safe_path(path).read_text(encoding="utf-8")


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write a text file in the workspace."""
    target = _safe_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} characters to {path}"


if __name__ == "__main__":
    server.run()
