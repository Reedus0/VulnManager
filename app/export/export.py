from pathlib import Path
import json


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

Дополнительно:
{r.get('note')}
""")

    path.write_text("\n\n" + "="*60 + "\n\n".join(blocks), encoding="utf-8")


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
