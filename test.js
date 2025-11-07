// 1) Insecure CORS (overly permissive) (CWE-942)
function cors_vuln_example(req, res) {
  // Vulnerable: allow all origins
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end('ok');
}

function cors_safe_example(req, res) {
  const allowed = ['https://example.com'];
  const origin = req.headers.origin;
  if (allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.end('ok');
}
// Fix: Fix: restrict origins; use established CORS middleware with whitelist.

// 2) SQL Injection - server-side pattern (CWE-89)
function getUserByName_vuln(db, name) {
  // Vulnerable: string concatenation for SQL
  const q = "SELECT id,name FROM users WHERE name = '" + name + "'";
  console.log("[DEBUG] constructed SQL:", q);
  // db.query(q, callback)  // DO NOT execute untrusted queries
  return q;
}

function getUserByName_safe(db, name) {
  // Safe: parameterized query / prepared statement
  const q = "SELECT id,name FROM users WHERE name = ?";
  // db.query(q, [name], callback)
  return { sql: q, params: [name] };
}
// Fix: Fix: use parameterized queries or ORM with binding.

// 3) Unsafe eval / Function (CWE-95)
function runUserCode_vuln(code) {
  // Vulnerable: directly executing user-supplied code
  console.log("[DEBUG] would eval code:", code);
  // const result = eval(code); // DO NOT eval untrusted code
  return "eval_skipped";
}

function runUserCode_safe(code) {
  // Safe: avoid eval; use sandboxed parser/interpreter or whitelist
  if (!/^[0-9+\-*/ ().]+$/.test(code)) throw new Error("Unsafe code");
  console.log("[DEBUG] validated arithmetic expression:", code);
  return "safe_eval_skipped";
}
// Fix: Fix: avoid eval; use vetted parsers or sandbox environments.

// 4) Insecure cookies / session handling (missing Secure/HttpOnly)
function setSession_vuln(res, token) {
  // Vulnerable: cookie without Secure or HttpOnly flags (sensitive)
  res.setHeader('Set-Cookie', `session=${token}; Path=/;`);
}

function setSession_safe(res, token) {
  // Safe: set Secure, HttpOnly, SameSite
  res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`);
}
// Fix: Fix: use secure cookie flags; rotate and store tokens server-side when possible.

// 5) Open redirect (CWE-601)
function redirect_vuln(res, target) {
  // Vulnerable: no validation of redirect target
  res.setHeader('Location', target);
  res.statusCode = 302;
  res.end();
}

function redirect_safe(res, target) {
  // Safe: validate against whitelist or build internal route map
  const allowed = ['/home', '/dashboard'];
  if (allowed.includes(target)) {
    res.setHeader('Location', target);
    res.statusCode = 302;
  } else {
    res.statusCode = 400;
    res.end('invalid redirect');
  }
}
// Fix: Fix: whitelist redirect destinations; use relative paths.

// 6) JWT misconfiguration (alg: none demonstration) (conceptual)
function jwt_vuln_example(token) {
  // Vulnerable: naive verification might skip alg checks (do NOT accept tokens with alg:none)
  console.log("[DEBUG] would parse token:", token);
  return "jwt_parse_skipped";
}

function jwt_safe_example(token) {
  // Safe: verify signature and algorithms explicitly with library
  return "jwt_verify_with_algorithms_and_keys";
}
// Fix: Fix: verify alg, use proper libraries and key rotation.

//// ===========================
//// Client-side (Browser) examples
//// ===========================

// 7) DOM XSS - unsafe innerHTML (CWE-79)
function dom_xss_vuln() {
  // vulnerable: inserting untrusted content directly
  const params = new URLSearchParams(window.location.search);
  const name = params.get('name') || '';
  const out = document.getElementById('out');
  // Dangerous:
  out.innerHTML = "Hello, " + name;
}

function dom_xss_safe() {
  const params = new URLSearchParams(window.location.search);
  const name = params.get('name') || '';
  const out = document.getElementById('out');
  // Safe:
  out.textContent = "Hello, " + name;
}
// Fix: Fix: use textContent, sanitize input, use templating that auto-escapes.

// 8) Storing sensitive data in localStorage / insecure storage
function store_token_vuln(token) {
  // Vulnerable: localStorage accessible to JS and XSS
  localStorage.setItem('token', token);
}

function store_token_safe(token) {
  // Safe: prefer httpOnly secure cookies for session tokens
  console.log("[DEBUG] should store token in httpOnly secure cookie, not localStorage");
}
// Fix: Fix: use HttpOnly secure cookies for sensitive tokens; protect against XSS.

// 9) Prototype pollution via unsafe merge (CWE-1321)
function merge_vuln(target, src) {
  for (let k in src) {
    target[k] = src[k];
  }
  return target;
}

// Safe merge: filter dangerous keys
function merge_safe(target, src) {
  const blacklist = ['__proto__', 'constructor', 'prototype'];
  for (let k in src) {
    if (blacklist.includes(k)) continue;
    target[k] = src[k];
  }
  return target;
}
// Fix: Fix: validate keys; disallow special prototype keys; use libraries that defend against pollution.

// 10) Prototype pollution demo (conceptual)
function pollute_demo() {
  const a = {};
  merge_vuln(a, JSON.parse('{"__proto__": {"isAdmin": true}}'));
  console.log("[DEBUG] after pollution, a.isAdmin:", a.isAdmin);
  return a;
}
// Fix: Fix: avoid merging untrusted objects, sanitize keys.

// 11) SSRF pattern (server-side) - do not perform network calls
function ssrf_vuln(targetUrl) {
  // Vulnerable: directly using user-supplied URL for server-side fetch
  console.log("[DEBUG] would fetch:", targetUrl);
  // fetch(targetUrl)  // DO NOT execute external requests in demo
  return "ssrf_skipped";
}

function ssrf_safe(targetUrl) {
  // Safe: validate and restrict to internal allowed hostnames
  const allowedHost = 'localhost';
  try {
    const u = new URL(targetUrl);
    if (u.hostname !== allowedHost) throw new Error('disallowed');
  } catch (e) {
    return 'invalid';
  }
  return 'ok_to_fetch_local';
}
// Fix: Fix: whitelist internal endpoints, restrict network egress.

// 12) Dependency / supply-chain demonstration (explanatory)
// Vulnerable pattern: requiring an unpinned/unvetted package (explain only)
// e.g., const shady = require('some-unpinned-package');
// Fix: Fix: pin versions, use SBOM, verify package integrity (lockfiles).

// 13) Insecure RNG (Math.random for tokens)
function token_vuln() {
  const t = Math.floor(Math.random() * 1e9).toString(16);
  console.log("[DEBUG] predictable token:", t);
  return t;
}

function token_safe() {
  // Safe: use Web Crypto API in browser or crypto.randomBytes in Node
  // In Node: require('crypto').randomBytes(16).toString('hex')
  return "use_crypto_random_in_real_code";
}
// Fix: Fix: use cryptographically secure RNG.

// ===========================
// Minimal demo runner (safe)
// ===========================
if (typeof require !== 'undefined' && require.main === module) {
  console.log("== DEMO: Inspect outputs -- no network or eval is executed ==");
  // Server-side demos (no network calls)
  console.log("CORS vuln header would be '*':", cors_vuln_example({},{setHeader:console.log}));
  console.log("SQL constructed (vuln):", getUserByName_vuln(null, "alice"));
  console.log("SQL param (safe):", JSON.stringify(getUserByName_safe(null, "alice")));
  console.log("Eval demo (vuln):", runUserCode_vuln("1+1"));
  console.log("cookie vuln (would set):", setSession_vuln({setHeader:console.log}, "TOKEN123"));
  console.log("redirect vuln (shows target):", redirect_vuln({setHeader:console.log, end:() => {}, statusCode:0}, "https://evil.example/"));
  // Client-side demos (only log, do not manipulate real DOM here)
  console.log("DOM XSS (safe alternative):", dom_xss_safe.toString().slice(0,200), "...");
  console.log("Prototype pollution demo (conceptual):", pollute_demo().isAdmin === true ? "polluted" : "safe");
  console.log("token vuln:", token_vuln());
  console.log("Demo complete. Use ESLint + security audit tools to find issues.");
}
