from pathlib import Path
from datetime import datetime

from app.core.queue_manager import load_queue, clear_queue
from app.core.cve_loader import fetch_cve
from app.core.bdu_loader import fetch_bdu
from app.export.export import save_json, save_text, save_html


OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)


def build_reports():
    id_list = load_queue()

    print(f"[CRON] Starting weekly scan: {len(id_list)} items")

    reports = []

    for identifier in id_list:
        try:
            if identifier.upper().startswith("CVE"):
                print(f"[CRON] fetching CVE {identifier}")
                reports.append(fetch_cve(identifier))
            else:
                print(f"[CRON] fetching BDU {identifier}")
                reports.append(fetch_bdu(identifier))
        except Exception as e:
            print(f"[CRON] ERROR {identifier}: {e}")
            reports.append({
                "id": identifier,
                "error": str(e)
            })

    return reports


def save_reports(reports):
    timestamp = datetime.now().strftime("%Y-%m-%d")

    name = "VulnerabilityReport_" + timestamp

    json_path = OUTPUT_DIR / f"{name}.json"
    html_path = OUTPUT_DIR / f"{name}.html"
    text_path = OUTPUT_DIR / f"{name}.txt"

    print("[CRON] saving reports...")

    save_json(reports, json_path)
    save_html(reports, html_path)
    save_text(reports, text_path)

    print(f"[CRON] saved:")
    print(json_path)
    print(html_path)
    print(text_path)


def main():
    reports = build_reports()

    save_reports(reports)

    print("[CRON] clearing queue...")
    clear_queue()

    print("[CRON] done")


if __name__ == "__main__":
    main()
