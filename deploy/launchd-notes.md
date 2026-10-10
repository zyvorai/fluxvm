# Running FluxVM unattended on a Mac mini or Mac Studio

Warm slots, hibernate and speculate restore saved VM state, and Virtualization.framework restores only in an unlocked login session.
So on a headless Mac the daemon runs as a LaunchAgent of a logged-in user, not as a system LaunchDaemon.

1. Create a dedicated user (for example `fluxvm`) and turn on automatic login for it (System Settings > Users & Groups).
2. Turn off the screen lock for that user (Lock Screen: "Require password after screen saver begins" set to never), and keep the
   display awake or attach a display emulator; Screen Sharing works for maintenance.
3. As that user, run `fluxctl --config ~/.config/fluxvm/fluxvm.toml service install`. It writes the agent below as
   `~/Library/LaunchAgents/dev.zyvor.fluxvm.plist` (with the path of the `fluxctl` you ran and the config's absolute path) and
   loads it with `launchctl bootstrap gui/$(id -u)`. Running it again replaces and reloads the agent, for example after moving
   `fluxctl`. `fluxctl service status` shows whether it is loaded and its PID; `fluxctl service uninstall` unloads and deletes it.

With Homebrew, `brew services start fluxvm` installs an equivalent LaunchAgent.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.zyvor.fluxvm</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/fluxctl</string>
    <string>--config</string><string>/Users/fluxvm/.config/fluxvm/fluxvm.toml</string>
    <string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>/Users/fluxvm/Library/Logs/fluxvm.log</string>
  <key>StandardErrorPath</key><string>/Users/fluxvm/Library/Logs/fluxvm.log</string>
</dict>
</plist>
```

Run `fluxvm-agent node` (see [kairon-node-mac.md](kairon-node-mac.md)) the same way, as a second agent with its own label.

If a restore fails anyway (locked screen, macOS updated since the snapshot), creates cold-boot and hibernated sandboxes cold-boot
on their next request; nothing is lost but the guest's memory.
