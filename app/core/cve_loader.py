import requests

NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_LABELS = [
    (0.1, "Низкий"),
    (4.0, "Средний"),
    (7.0, "Высокий"),
    (9.0, "Критический"),
]


def severity_label(cvss_score):
    if cvss_score is None:
        return "Неизвестный"
    try:
        score = float(cvss_score)
    except (TypeError, ValueError):
        return "Неизвестный"
    label = "Неизвестный"
    for threshold, name in SEVERITY_LABELS:
        if score >= threshold:
            label = name
    return label


def fetch_cve(cve_id):
    params = {"cveId": cve_id.strip()}
    headers = {"Accept": "application/json"}

    response = requests.get(
        NIST_API_URL,
        params=params,
        headers=headers,
        timeout=15
    )

    if response.status_code == 404:
        raise ValueError(f"CVE {cve_id} not found")

    response.raise_for_status()

    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])

    if not vulnerabilities:
        raise ValueError(f"CVE {cve_id} not found in NIST database")

    vulnerability = vulnerabilities[0]

    return build_report(vulnerability)


def extract_description(cve):
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return item["value"].strip()
    if descriptions:
        return descriptions[0].get("value", "").strip()
    return ""


def translate_to_russian(text):
    if not text:
        return ""
    url = "https://translate.googleapis.com/translate_a/single"
    params = {
        "client": "gtx",
        "sl": "en",
        "tl": "ru",
        "dt": "t",
        "q": text,
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list) and data:
            translated = "".join([segment[0]
                                  for segment in data[0] if segment and segment[0]])
            return translated.strip()
    except requests.RequestException:
        pass
    return text


def extract_cvss_score(cve):
    metrics = cve.get("metrics", {})
    print(metrics)
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name, [])
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        if score is not None:
            return score
    return None


def extract_attack_vector(cve):
    metrics = cve.get("metrics", {})

    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_name, [])
        if not entries:
            continue

        preferred = next(
            (entry for entry in entries if entry.get("type") == "Primary"),
            None
        )

        entry = preferred or entries[0]

        cvss_data = entry.get("cvssData", {})
        vector = cvss_data.get("vectorString")

        if vector:
            if "/" in vector:
                return vector.split("/", 1)[1]

    return ""


def extract_notes(cve):
    references = cve.get("references", [])
    notes = []
    for ref in references:
        url = ref.get("url")
        if not url:
            continue
        else:
            notes.append(url)
    return "\n".join(notes)


def build_report(vulnerability):
    cve = vulnerability.get("cve", {})
    description_en = extract_description(cve)
    report = {
        "id": cve.get("id", ""),
        "severity": severity_label(extract_cvss_score(cve)),
        "cvss_score": extract_cvss_score(cve),
        "description": translate_to_russian(description_en),
        "attack_vector": extract_attack_vector(cve),
        "note": extract_notes(cve),
        "source": "nist",
    }
    return report
