from pathlib import Path
import json
from datetime import datetime, timedelta

from docxtpl import DocxTemplate


def save_json(reports: list[dict], path: Path):
    path.write_text(
        json.dumps(reports, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def save_text(reports: list[dict], path: Path):
    blocks = []

    for r in reports:
        if "error" in r:
            blocks.append(f"""
ID: {r['id']}
ERROR: {r['error']}
""")
            continue

        blocks.append(f"""
{r.get('id')}
Критичность: {r.get('severity')}

{r.get('description')}
""")

    path.write_text("\n".join(blocks), encoding="utf-8")


def save_html(reports: list[dict], path: Path):
    html = """
<html>
<head>
<meta charset="utf-8">
<title>Vulnerability Report</title>
<style>
body { font-family: Arial; }
.card {
    border: 1px solid #ccc;
    margin: 10px;
    padding: 10px;
}
</style>
</head>
<body>
<h1>Vulnerability Report</h1>
"""

    for r in reports:
        if "error" in r:
            html += f"""
            <div class="card">
                <h2>{r.get('id')}</h2>
                <p style="color:red;">ERROR: {r.get('error')}</p>
            </div>
            """
            continue

        html += f"""
        <div class="card">
            <h2>{r.get('id')}</h2>
            <p><b>Критичность:</b> {r.get('severity')}</p>
            <p><b>CVSS:</b> {r.get('cvss_score')}</p>
            <p><b>Вектор атаки:</b> {r.get('attack_vector')}</p>

            <h3>Описание</h3>
            <p>{r.get('description')}</p>

            <h3>Дополнительно</h3>
            <pre>{r.get('note')}</pre>
        </div>
        """

    html += """
</body>
</html>
"""

    path.write_text(html, encoding="utf-8")


def get_dates():
    months = {
        1: "января", 2: "февраля", 3: "марта", 4: "апреля",
        5: "мая", 6: "июня", 7: "июля", 8: "августа",
        9: "сентября", 10: "октября", 11: "ноября", 12: "декабря"
    }

    def format_dt(dt):
        return f"«{dt.day:02d}» {months[dt.month]} {dt.year}"

    today = datetime.today()
    week_ago = today - timedelta(days=7)

    return {
        "today": format_dt(today),
        "week_ago": format_dt(week_ago)
    }


def save_docx(reports: list, output_path: Path, template_path="template.docx"):
    doc = DocxTemplate(template_path)
    dates = get_dates()
    for r in reports:
        r["attack_vector"] = r.get("attack_vector", "").replace("/", "/\n")
    context = {
        "date_first": dates["week_ago"],
        "date_last": dates["today"],
        "reports": reports
    }
    doc.render(context)
    doc.save(output_path)
