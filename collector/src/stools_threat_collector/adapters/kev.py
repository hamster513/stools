def parse_kev(data):
    documents = []
    for entry in data["vulnerabilities"]:
        cve = entry["cveID"].upper()
        documents.append({"external_id": cve, "title": entry["vulnerabilityName"],
                          "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}",
                          "links": [f"https://nvd.nist.gov/vuln/detail/{cve}"],
                          "text": entry.get("shortDescription", "") + "\n" + entry.get("requiredAction", ""),
                          "published_at": entry["dateAdded"] + "T00:00:00+00:00",
                          "identifiers": [cve], "exploitation_confirmed": True,
                          "evidence_kind": "kev", "full_text": True})
    return documents


def collect(source, checkpoint, fetcher):
    return parse_kev(fetcher.get(source["url"]).json()), {}
