"""Line-based scan progress, emitted by the collecting thread and flushed immediately."""
from collections import Counter
from time import monotonic


class ConsoleProgress:
    def __init__(self, label="scan"):
        self.label = label
        self.started = monotonic()
        self.counts = Counter()
        self.attempted = 0
        self.announced = False

    def __call__(self, completed, total, finding):
        elapsed = monotonic() - self.started
        prefix = "[{} {}/{} {:5.1f}% | {:.1f}s]".format(
            self.label, completed, total, 100 * completed / total if total else 100, elapsed)
        if finding is None:
            message = "Waiting for responses" if self.announced else "Starting checks"
            self.announced = True
            print("{} {}; {} unfinished.".format(prefix, message, total - completed), flush=True)
        else:
            status = finding.get("status", "unknown")
            self.counts[status] += 1
            self.attempted += bool(finding.get("attempted"))
            site = finding.get("name") or finding.get("site", "unknown site")
            if finding.get("adult"):
                site = "[PORN/ADULT] " + site
            detail = finding.get("detail", "")
            http = " HTTP {}".format(finding["http_status"]) if finding.get("http_status") is not None else ""
            # Keep one result per line even when a provider returns control characters.
            message = "{}: {}{}{}".format(site, status, http, " — " + detail if detail else "")
            message = " ".join(message.split())
            print("{} {}".format(prefix, message), flush=True)
        if completed == total:
            counts = ", ".join("{}={}".format(key, count) for key, count in sorted(self.counts.items()))
            print("{} complete: {} results, {} attempted; {}".format(
                self.label, total, self.attempted, counts or "no checks"), flush=True)
