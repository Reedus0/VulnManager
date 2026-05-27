import html
import json
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def normalize_bdu_id(value):
    if not value:
        return ""
    value = value.strip()
    if value.upper().startswith("BDU:"):
        value = value.split(":", 1)[1]
    if value.startswith("http://") or value.startswith("https://"):
        value = value.rstrip("/").split("/")[-1]
    return value


def fetch_bdu_html(bdu_id):
    normalized_id = normalize_bdu_id(bdu_id)
    if not normalized_id:
        raise ValueError("Empty BDU identifier")

    url = f"https://bdu.fstec.ru/vul/{normalized_id}"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers, timeout=15, verify=False)
    if response.status_code == 404:
        raise ValueError(f"BDU {bdu_id} not found")
    response.raise_for_status()
    return response.text


def _extract_js_object(html_text, key_name="const v_model"):
    pattern = re.compile(
        rf'{re.escape(key_name)}\s*=\s*reactive\s*\(\s*', re.DOTALL)
    match = pattern.search(html_text)
    if not match:
        return None

    start = match.end()
    brace_start = html_text.find("{", start)
    if brace_start == -1:
        return None

    depth = 0
    in_string = False
    escape = False
    quote_char = None
    for idx in range(brace_start, len(html_text)):
        ch = html_text[idx]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote_char:
                in_string = False
        else:
            if ch == '"' or ch == "'":
                in_string = True
                quote_char = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return html_text[brace_start:idx + 1]
    return None


def _parse_js_object(html_text):
    obj_text = _extract_js_object(html_text, "const v_model")
    if obj_text is None:
        obj_text = _extract_js_object(html_text, "v_model")
    if obj_text is None:
        return None

    try:
        return json.loads(obj_text)
    except json.JSONDecodeError:
        return None


def _extract_links(text):
    if not text:
        return []
    links = re.findall(r'href="([^"]+)"', text)
    links += re.findall(r'https?://[^"\s<>]+', text)
    return list(dict.fromkeys(links))


def parse_bdu_html(html_text, requested_id=None):
    report = {
        "id": "",
        "severity": "UNKNOWN",
        "cvss_score": None,
        "description": "",
        "attack_vector": "",
        "note": "",
        "source": "bdu",
    }

    model = _parse_js_object(html_text)
    if model is None:
        return report

    report["id"] = requested_id
    report["description"] = html.unescape(model.get("vul_desc", ""))

    vul_critu = model.get("vul_critu", "")
    if vul_critu:
        score_match = re.search(r'([0-9]+(?:[\.,][0-9]+)?)', vul_critu)
        if score_match:
            try:
                report["cvss_score"] = float(
                    score_match.group(1).replace(",", "."))
            except ValueError:
                report["cvss_score"] = None

    if report["cvss_score"] is not None:
        if report["cvss_score"] >= 9.0:
            report["severity"] = "Критический"
        elif report["cvss_score"] >= 7.0:
            report["severity"] = "Высокий"
        elif report["cvss_score"] >= 4.0:
            report["severity"] = "Средний"
        else:
            report["severity"] = "Низкий"

    cvss_values = model.get("cvsses3") or model.get(
        "cvsses4") or model.get("cvsses") or []
    for value in cvss_values:
        if isinstance(value, str):
            inner = re.search(r'>([^<]+)<', value)
            if inner:
                report["attack_vector"] = inner.group(1).strip()
                break
            parts = value.split(":", 1)
            if len(parts) == 2:
                report["attack_vector"] = parts[1].strip()
                break

    notes = []
    notes.extend(_extract_links(model.get("vul_link", "")))
    notes.extend(_extract_links(model.get("vul_vmer", "")))
    notes.extend(_extract_links(model.get("vul_note", "")))
    for item in model.get("idvals", []):
        if isinstance(item, str):
            notes.extend(_extract_links(item))

    if model.get("vul_fix"):
        notes.append(html.unescape(model.get("vul_fix")))
    if model.get("vul_refdat"):
        notes.append(html.unescape(model.get("vul_refdat")))

    report["note"] = "\n".join([note for note in notes if note])
    return report


def fetch_bdu(bdu_id):
    html_text = fetch_bdu_html(bdu_id)
    report = parse_bdu_html(html_text, requested_id=bdu_id)
    return report
