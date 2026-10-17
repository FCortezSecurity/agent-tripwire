from mcp.server import MCPServer

NOTES = {
    "1": {"title": "Team meeting", "text": "Standup moved to 10am. Bring the Q3 roadmap."},
    "2": {"title": "Shopping list", "text": "Coffee, notebooks, USB cable."},
    "3": {"title": "Project ideas", "text": "Write up the honeypot results."},
}

server = MCPServer("notes")


@server.tool()
def list_notes() -> list[dict]:
    """List all notes with their ids and titles."""
    return [{"id": k, "title": v["title"]} for k, v in NOTES.items()]


@server.tool()
def get_note(note_id: str) -> str:
    """Get the text of a note by id."""
    if note_id not in NOTES:
        raise ValueError("note not found")
    return NOTES[note_id]["text"]


@server.tool()
def search_notes(query: str) -> list[str]:
    """Return ids of notes whose title or text contains the query."""
    q = query.lower()
    return [k for k, v in NOTES.items() if q in v["title"].lower() or q in v["text"].lower()]


if __name__ == "__main__":
    server.run()
