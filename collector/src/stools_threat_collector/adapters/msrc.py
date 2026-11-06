from datetime import datetime, timedelta, timezone


def parse_cvrf(data):
    documents = []
    for item in data.get("Vulnerability", []):
        cve = item.get("CVE", "")
        if not cve:
            continue
        history = item.get("RevisionHistory", [])
        published = history[0].get("Date") if history else None
        updated = history[-1].get("Date") if history else None
        notes = "\n".join(str(note.get("Value", "")) for note in item.get("Notes", []))
        threats = [str(threat.get("Description", {}).get("Value", "")) for threat in item.get("Threats", [])]
        confirmed = any("exploited:yes" in text.lower().replace(" ", "") for text in threats)
        documents.append({"external_id": cve, "title": item.get("Title", {}).get("Value", cve),
                          "url": "https://msrc.microsoft.com/update-guide/vulnerability/" + cve,
                          "text": (notes + "\n" + "\n".join(threats))[:262144],
                          "published_at": published, "updated_at": updated,
                          "identifiers": [cve], "exploitation_confirmed": confirmed,
                          "evidence_kind": "vendor", "full_text": True})
    return documents


def collect(source, checkpoint, fetcher):
    # Monthly CVRF contains product trees for hundreds of vulnerabilities.
    # Keep a bounded allowance separate from the 5 MiB news/HTML limit.
    fetcher.max_bytes = 32 * 1024 * 1024
    headers = {"Accept": "application/json"}
    updates = fetcher.get(source["url"], headers).json()["value"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    documents = []
    for entry in sorted(updates, key=lambda row: row.get("CurrentReleaseDate", ""), reverse=True)[:3]:
        date = entry.get("CurrentReleaseDate", "")
        if date and datetime.fromisoformat(date.replace("Z", "+00:00")) < cutoff:
            continue
        url = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + entry["ID"]
        documents.extend(parse_cvrf(fetcher.get(url, headers).json()))
    return documents, {}
