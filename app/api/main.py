from pathlib import Path
import os
from uuid import uuid4

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates

from app.core.cve_loader import fetch_cve
from app.core.bdu_loader import fetch_bdu

from app.core.queue_manager import (
    load_queue,
    add_item,
    remove_item
)

from app.export.export import save_json, save_text, save_html

app = FastAPI()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ---------------- UI ----------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
    )


# ---------------- QUEUE API ----------------

@app.get("/queue")
def get_queue():
    return load_queue()


@app.post("/queue/add")
def queue_add(identifier: str = Form(...)):
    add_item(identifier)
    return {"status": "ok"}


@app.post("/queue/remove")
def queue_remove(identifier: str = Form(...)):
    remove_item(identifier)
    return {"status": "ok"}


# ---------------- MANUAL GENERATE ----------------

@app.post("/generate")
def generate(format: str = Form("json")):
    id_list = load_queue()

    reports = []

    for identifier in id_list:
        try:
            if identifier.upper().startswith("CVE"):
                reports.append(fetch_cve(identifier))
            else:
                reports.append(fetch_bdu(identifier))
        except Exception as e:
            reports.append({
                "id": identifier,
                "error": str(e)
            })

    out_dir = Path(os.getenv("OUTPUT_DIR", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)

    file_id = uuid4().hex
    file_path = out_dir / f"report_{file_id}.{format}"

    if format == "json":
        save_json(reports, file_path)
    elif format == "text":
        save_text(reports, file_path)
    else:
        save_html(reports, file_path)

    return FileResponse(
        path=file_path,
        filename=file_path.name,
        media_type="application/octet-stream"
    )


@app.get("/output/files")
def list_output_files():
    out_dir = Path(os.getenv("OUTPUT_DIR", "./output"))

    if not out_dir.exists():
        return {"files": []}

    files = [
        {
            "name": f.name,
            "size": f.stat().st_size
        }
        for f in out_dir.iterdir()
        if f.is_file()
    ]

    return {"files": files}


@app.get("/output/download/{filename}")
def download_file(filename: str):
    out_dir = Path(os.getenv("OUTPUT_DIR", "./output"))
    file_path = out_dir / filename

    if not file_path.exists():
        return {"error": "file not found"}

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream"
    )
