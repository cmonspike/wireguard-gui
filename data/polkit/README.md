# Polkit configuration for fewer prompts

The GUI performs privileged actions through:

```text
pkexec /usr/libexec/wireguard-gui-helper …
```

Without a custom rule, Polkit can prompt for each operation (`up`, `down`, import, create, delete).

To minimize prompts while keeping privilege scope tight, install the rule template in this folder:

```bash
sudo install -Dm644 data/polkit/30-wireguard-gui.rules /etc/polkit-1/rules.d/30-wireguard-gui.rules
```

Recommended behavior in the provided rule:

- Match only `org.freedesktop.policykit.exec`
- Match only program `/usr/libexec/wireguard-gui-helper`
- Require a local active session user
- Return `AUTH_ADMIN_KEEP` so the user authenticates once and Polkit reuses authorization for a while

Notes:

- `AUTH_ADMIN_KEEP` does not mean "never prompt again"; it reduces prompt frequency via Polkit caching.
- Cache duration is controlled by Polkit/agent and distribution defaults.
- If your distro does not expose `action.lookup("program")`, keep default prompts or adapt the rule carefully.
