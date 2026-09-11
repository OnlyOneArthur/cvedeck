from __future__ import annotations

import shutil
import subprocess


def desktop_notify(cve_id: str, event: str) -> bool:
    command = shutil.which("notify-send")
    if command is None:
        return False
    label = "became known exploited" if event == "BECAME_KEV" else "is newly critical"
    try:
        result = subprocess.run(
            [command, "CVEDeck", f"{cve_id} {label}"], check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0
