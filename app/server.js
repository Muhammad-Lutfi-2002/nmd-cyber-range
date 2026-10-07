/**
 * Admin Feedback System — INTENTIONALLY VULNERABLE (Cyber Range Lab)
 * Scenario 75: "Cookie Reuse & MFA Bypass"
 *
 * This app is deliberately insecure for Red vs Blue training purposes.
 * DO NOT deploy outside an isolated lab network.
 *
 * Bug chain (for the write-up / presentation):
 *  1. Reflected/stored XSS in the feedback box bypasses a naive keyword-based WAF
 *     using <svg onload=...> instead of <script>.
 *  2. The pre-auth cookie (pre_mfa_session) is readable by JavaScript (HttpOnly=false),
 *     so a stolen admin session cookie (adm_sess) could be exfiltrated the same way.
 *  3. The REAL bug: /dashboard only checks "does an adm_sess cookie exist?" — it never
 *     verifies that /api/verify-mfa was actually completed server-side. So replaying
 *     (or simply forging) an adm_sess cookie gets you straight into the admin
 *     dashboard, completely skipping MFA.
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const PORT = 3075;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ---------------------------------------------------------------------------
// PHASE 1: RECON — expose tech stack + hide hints in headers / robots.txt
// ---------------------------------------------------------------------------

// Express sets "X-Powered-By: Express" by default — override it to be explicit.
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Node.js');
  next();
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    [
      'User-agent: *',
      'Disallow: /api/verify-mfa',
      'Disallow: /dashboard',
      '',
    ].join('\n')
  );
});

// In-memory "last submitted feedback" — this is what gets reflected (unescaped!)
// on the admin dashboard. Stored XSS lives here.
let lastFeedback = '(no feedback submitted yet)';

const ASCII_HINT = `
  ___ ___ ___ _  _ _____ _____ ___
 / __| __/ __| || |_   _|_   _/ __|
 \\__ \\ _| (__| __ | | |   | | \\__ \\
 |___/___\\___|_||_| |_|   |_| |___/

  Hint for curious visitors: every good crawler reads robots.txt first.
  (SCENARIO75{robots.txt})
`;

app.get('/', (req, res) => {
  // Pre-authentication session cookie. HttpOnly is explicitly FALSE — this is
  // part of the vulnerability (anything JS on this origin can read it, and in
  // a real exploit chain, so could an attacker's injected script).
  res.cookie('pre_mfa_session', 'pending_mfa_verification', {
    httpOnly: false,
    sameSite: 'Lax',
  });

  res.send(`<!doctype html>
<html>
<head>
  <title>Admin Feedback System</title>
  <!--
${ASCII_HINT}
  -->
</head>
<body>
  <h1>Corporate Admin Feedback System</h1>
  <p>Internal tool. Submit feedback below — our admins review it shortly.</p>

  <form method="POST" action="/feedback">
    <textarea name="comment" rows="4" cols="50" placeholder="Your feedback..."></textarea><br/>
    <button type="submit">Submit Feedback</button>
  </form>

  <p>Admins: <a href="/api/verify-mfa">Verify MFA to access the dashboard</a></p>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// PHASE 2: DEFENSE EVASION — naive WAF, bypassable via <svg onload=...>
// ---------------------------------------------------------------------------

function naiveWaf(input) {
  // Only blocks the literal <script tag (case-insensitive). This is the bug:
  // it does NOT catch other HTML5 event-handler vectors like <svg onload=...>.
  return /<script/i.test(input);
}

app.post('/feedback', (req, res) => {
  const comment = req.body.comment || '';

  if (naiveWaf(comment)) {
    // WAF caught a <script> tag -> block it.
    return res.status(403).send('Blocked by WAF: <script> payloads are not allowed.');
  }

  // Anything else (including <svg onload=...> XSS payloads) passes straight through
  // and gets stored, unescaped, for later reflection on /dashboard.
  lastFeedback = comment;

  res.send(
    'Thank you! Your feedback has been submitted and will be reviewed by an administrator shortly.'
  );
});

// ---------------------------------------------------------------------------
// PHASE 3: INITIAL ACCESS — MFA bypass via session logic flaw
// ---------------------------------------------------------------------------

// The "legitimate" MFA flow — included so the app is functionally complete.
app.get('/api/verify-mfa', (req, res) => {
  res.send(`<!doctype html>
<html><body>
  <h1>MFA Verification</h1>
  <form method="POST" action="/api/verify-mfa">
    <input type="text" name="otp" placeholder="Enter 6-digit OTP" />
    <button type="submit">Verify</button>
  </form>
  <p><em>Demo OTP: 123456</em></p>
</body></html>`);
});

app.post('/api/verify-mfa', (req, res) => {
  if (req.body.otp === '123456') {
    const token = 'adm_sess_' + crypto.randomBytes(12).toString('hex');
    // NOTE: in a hardened app this session token would be stored server-side
    // (e.g. in Redis) and validated on every request. Here it is NOT — the
    // dashboard route below only checks whether the cookie exists at all.
    res.cookie('adm_sess', token, { httpOnly: false, sameSite: 'Lax' });
    return res.redirect('/dashboard');
  }
  res.status(401).send('Invalid OTP.');
});

// THE VULNERABLE ROUTE: trusts any adm_sess cookie, never re-checks MFA.
app.get('/dashboard', (req, res) => {
  const sessionCookie = req.cookies.adm_sess;

  if (!sessionCookie) {
    // No admin cookie at all -> must go through MFA first (this part is fine).
    return res.redirect('/api/verify-mfa');
  }

  // BUG: we never verify this token against a server-side session store, and
  // we never check that /api/verify-mfa actually ran for this client. Any
  // client presenting ANY non-empty adm_sess cookie gets in — including a
  // forged one, or a legitimate admin's cookie replayed by an attacker who
  // stole it via the stored XSS above.
  res.send(`<!doctype html>
<html>
<head><title>Admin Dashboard</title></head>
<body>
  <h1>Admin Dashboard</h1>
  <p>Session token accepted: <code>${sessionCookie}</code></p>

  <h2>Latest Feedback Submission</h2>
  <div class="xss-payload">${lastFeedback}</div>

  <!-- SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d} -->
  <div style="display:none">SCENARIO75{RED_C00k13_MFA_Byp4ss_0wn3d}</div>
</body>
</html>`);
});

// Simple collector endpoint representing "the attacker's server" receiving an
// exfiltrated cookie via fetch() from the injected XSS payload. Useful for a
// live demo during the presentation.
app.get('/collect', (req, res) => {
  console.log(`[COLLECTOR] Exfiltrated data received: ${JSON.stringify(req.query)}`);
  res.status(204).end();
});

app.listen(PORT, () => {
  console.log(`Admin Feedback System listening on port ${PORT}`);
});
