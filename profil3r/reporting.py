"""Presentation of existing findings using site-category metadata."""
from profil3r.site_probe import is_adult


SECTIONS = (("general", "General"), ("porn_adult_sites", "Porn / adult sites"))


def annotate_findings(findings):
    rows = []
    for finding in findings:
        adult = bool(finding.get("adult")) or is_adult(finding)
        row = {**finding, "adult": adult,
               "section": "porn_adult_sites" if adult else "general"}
        if adult:
            row["category_note"] = "Porn/adult website category; not confirmation of account ownership."
        rows.append(row)
    return rows


def print_findings(findings):
    rows = annotate_findings(findings)
    for key, label in SECTIONS:
        group = [row for row in rows if row["section"] == key]
        if not group:
            continue
        print("\n{} ({} findings):".format(label, len(group)))
        if key == "porn_adult_sites":
            print("  Site category only; these results do not confirm account ownership.")
        for row in group:
            badge = "[PORN/ADULT] " if row["adult"] else ""
            detail = " — " + str(row["detail"]) if row.get("detail") else ""
            line = "  {}{}: {} ({}){}".format(
                badge, row.get("type", "finding"), row.get("site", row.get("value", "")),
                row.get("status", "unknown"), detail)
            print("  " + " ".join(line.split()))
