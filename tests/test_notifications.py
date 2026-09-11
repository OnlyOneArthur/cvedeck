import subprocess
from unittest.mock import Mock, patch

from cvedeck.notifications import desktop_notify


def test_notification_is_delivered_only_on_successful_process() -> None:
    with patch("cvedeck.notifications.shutil.which", return_value="/usr/bin/notify-send"), patch(
        "cvedeck.notifications.subprocess.run", return_value=Mock(returncode=1)
    ):
        assert not desktop_notify("CVE-2026-1234", "NEW_CRITICAL")


def test_notification_reports_missing_command() -> None:
    with patch("cvedeck.notifications.shutil.which", return_value=None):
        assert not desktop_notify("CVE-2026-1234", "BECAME_KEV")


def test_notification_timeout_is_not_delivered() -> None:
    with patch("cvedeck.notifications.shutil.which", return_value="/usr/bin/notify-send"), patch(
        "cvedeck.notifications.subprocess.run",
        side_effect=subprocess.TimeoutExpired("notify-send", 5),
    ):
        assert not desktop_notify("CVE-2026-1234", "NEW_CRITICAL")
