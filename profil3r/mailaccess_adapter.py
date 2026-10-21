"""Optional MailAccess CLI adapter.

Runs upstream MailAccess directly rather than claiming its 5,300+ platform
corpus is bundled or reimplemented by Profil3r.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def investigate_with_mailaccess(email, timeout=900):
    binary = shutil.which("mailaccess")
    if not binary:
        raise RuntimeError(
            "MailAccess is not installed. In your virtualenv run: "
            "python -m pip install mailaccess"
        )
    with tempfile.TemporaryDirectory(prefix="profil3r-mailaccess-") as directory:
        output = Path(directory) / "mailaccess.json"
        try:
            process = subprocess.run(
                [binary, "investigate", email, "-o", str(output)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("MailAccess exceeded the configured timeout") from exc
        if process.returncode:
            message = (process.stderr or process.stdout).strip()
            raise RuntimeError("MailAccess exited with status {}: {}".format(
                process.returncode, message[-400:]))
        if not output.is_file():
            raise RuntimeError("MailAccess finished without producing a JSON report")
        try:
            result = json.loads(output.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("MailAccess produced invalid JSON") from exc
        return {"type": "mailaccess", "status": "completed",
                "note": "Upstream MailAccess determines its platform coverage; "
                        "its default investigation is not an exhaustive scan of every corpus site.",
                "report": result}
