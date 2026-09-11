# Optional scheduling

CVEDeck installs no daemon and never modifies scheduling configuration.

Create `~/.config/systemd/user/cvedeck-sync.service`:

```ini
[Unit]
Description=Synchronize CVEDeck data

[Service]
Type=oneshot
ExecStart=%h/.local/bin/cvedeck sync
```

Create `~/.config/systemd/user/cvedeck-sync.timer`:

```ini
[Unit]
Description=Daily CVEDeck synchronization

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=30m

[Install]
WantedBy=timers.target
```

Enable only if desired:

```bash
systemctl --user daemon-reload
systemctl --user enable --now cvedeck-sync.timer
systemctl --user list-timers cvedeck-sync.timer
```

Rollback:

```bash
systemctl --user disable --now cvedeck-sync.timer
rm ~/.config/systemd/user/cvedeck-sync.{service,timer}
systemctl --user daemon-reload
```
