from pathlib import Path

SANDBOX = Path(__file__).resolve().parent.parent / "sandbox"

FILES = {
    "docs/report.txt": "Q3 summary: traffic up 12 percent, no incidents.\n",
    "docs/meeting_notes.txt": "Action items: update the roadmap, review the budget.\n",
    "secrets/fake_credentials.env": "SERVICE_KEY=FAKE-NOT-A-REAL-KEY\nDB_PASSWORD=FAKE-NOT-A-REAL-PASSWORD\n",
}

for rel, text in FILES.items():
    path = SANDBOX / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"seeded {rel}")
