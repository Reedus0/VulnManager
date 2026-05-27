from pathlib import Path
import json

QUEUE_FILE = Path("data/queue.json")
QUEUE_FILE.parent.mkdir(exist_ok=True)


def load_queue():
    if not QUEUE_FILE.exists():
        return []
    return json.loads(QUEUE_FILE.read_text(encoding="utf-8"))


def save_queue(queue):
    QUEUE_FILE.write_text(
        json.dumps(queue, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def add_item(identifier: str):
    queue = load_queue()
    if identifier not in queue:
        queue.append(identifier)
    save_queue(queue)


def remove_item(identifier: str):
    queue = load_queue()
    queue = [x for x in queue if x != identifier]
    save_queue(queue)


def clear_queue():
    save_queue([])
