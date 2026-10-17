import json
from datetime import UTC, datetime
from pathlib import Path

from mcp.server import MCPServer

ROOT = Path(__file__).resolve().parent.parent
OUTBOX = ROOT / "logs" / "outbox.jsonl"

server = MCPServer("email")


@server.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    OUTBOX.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "to": to,
        "subject": subject,
        "body": body,
    }
    with OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return f"Email sent to {to}"


if __name__ == "__main__":
    server.run()
