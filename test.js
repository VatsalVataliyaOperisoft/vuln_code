/**
 * educational vulnerable example
 * For defensive/educational use only. Do not deploy.
 *
 * Single-file React app demonstrating 15 distinct frontend vulnerabilities.
 * Each vulnerable snippet is labeled /* VULN X: <name> */ with a one-line mitigation comment.
 */

import React, { useState, useEffect, useRef } from "react";

export default function VulnerableDemo() {
  const [userInput, setUserInput] = useState("<script>alert(1)</script>");
  const [svgInput, setSvgInput] = useState('<svg><text>hello</text></svg>');
  const [codeInput, setCodeInput] = useState("console.log('unsafe')");
  const [funcInput, setFuncInput] = useState("return 2+2");
  const [counter, setCounter] = useState(0);
  const msgListenerRef = useRef(null);

  // --------------------------
  // VULN 1: DOM XSS via innerHTML
  // --------------------------
  // This directly injects user content into the DOM.
  function DangerousInnerHTML() {
    return (
      <div>
        {/* VULN 1: DOM XSS via innerHTML */}
        <div id="dom-xss" dangerouslySetInnerHTML={{ __html: userInput }} />
        {/* MITIGATION: Sanitize userInput with a robust sanitizer (e.g., DOMPurify) before inserting. */}
      </div>
    );
  }

  // --------------------------
  // VULN 2: dangerouslySetInnerHTML with SVG (SVG can include scripts)
  // --------------------------
  function DangerousSVG() {
    return (
      <div>
        {/* VULN 2: dangerouslySetInnerHTML for SVG content */}
        <div
          aria-label="svg-area"
          dangerouslySetInnerHTML={{ __html: svgInput }}
        />
        {/* MITIGATION: Validate and sanitize SVG; prefer using safe SVG element construction instead. */}
      </div>
    );
  }

  // --------------------------
  // VULN 3: Using eval on user input
  // --------------------------
  function runEval() {
    try {
      /* VULN 3: eval(user input) */
      // eslint-disable-next-line no-eval
      const result = eval(codeInput);
      // MITIGATION: Do not use eval; use safe parsers or whitelist of allowed operations.
      alert("Eval result: " + String(result));
    } catch (e) {
      alert("Eval error");
    }
  }

  // --------------------------
  // VULN 4: Using new Function with user input
  // --------------------------
  function runNewFunction() {
    try {
      /* VULN 4: new Function(user input) */
      const Fn = new Function(funcInput);
      const res = Fn();
      // MITIGATION: Avoid dynamic code generation; use safer abstractions or explicit whitelisting.
      alert("Function result: " + String(res));
    } catch (e) {
      alert("Function error");
    }
  }

  // --------------------------
  // VULN 5: Weak token generation using Math.random()
  // --------------------------
  function generateWeakToken() {
    /* VULN 5: Insecure token with Math.random() */
    const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    // MITIGATION: Use a cryptographically secure RNG (window.crypto.getRandomValues).
    alert("Weak token: " + token);
  }

  // --------------------------
  // VULN 6: Hardcoded API key in source
  // --------------------------
  // VULN 6: HARD-CODED API KEY (placeholder shown)
  const HARD_CODED_API_KEY = "API_KEY_PLACEHOLDER";
  // MITIGATION: Keep keys in secure vaults or environment variables; never commit to source.

  // --------------------------
  // VULN 7: Storing JWT in localStorage (persistent and accessible to JS)
  // --------------------------
  function storeJwtInLocalStorage() {
    /* VULN 7: storing JWT in localStorage */
    const fakeJwt = "eyJhbGci...FAKE.JWT.TOKEN";
    localStorage.setItem("auth_token", fakeJwt);
    // MITIGATION: Use secure, HttpOnly cookies for auth tokens to prevent XSS access.
    alert("JWT stored in localStorage (insecure).");
  }

  // --------------------------
  // VULN 8: Sending credentials in URL (GET query)
  // --------------------------
  async function sendCredentialsInUrl() {
    /* VULN 8: sending credentials in URL */
    const user = encodeURIComponent("alice");
    const pass = encodeURIComponent("password123");
    // This would leak credentials in logs and referer headers.
    await fetch(`https://api.example.invalid/login?user=${user}&pass=${pass}`);
    // MITIGATION: Use POST with HTTPS and send credentials in request body; use proper auth flows.
    alert("Sent credentials in URL (insecure).");
  }

  // --------------------------
  // VULN 9: Open redirect (unvalidated redirect param)
  // --------------------------
  function handleRedirect() {
    /* VULN 9: open redirect via unvalidated param */
    const params = new URLSearchParams(window.location.search);
    const to = params.get("returnTo") || "/home";
    // UNSAFE: directly redirecting to user-provided URL
    window.location.href = to;
    // MITIGATION: Validate redirects against a whitelist of allowed hosts/paths.
  }

  // --------------------------
  // VULN 10: postMessage without origin check
  // --------------------------
  useEffect(() => {
    /* VULN 10: postMessage listener without origin check */
    function onMessage(e) {
      // No origin validation -> trusting any origin
      console.log("Received message (no origin check):", e.data);
      // MITIGATION: Always verify event.origin against expected trusted origins.
    }
    window.addEventListener("message", onMessage);
    msgListenerRef.current = onMessage;
    return () => window.removeEventListener("message", msgListenerRef.current);
  }, []);

  // --------------------------
  // VULN 11: Insecure WebSocket (ws, not wss)
  // --------------------------
  const wsRef = useRef(null);
  function openInsecureWebSocket() {
    /* VULN 11: insecure ws:// WebSocket connection */
    try {
      wsRef.current = new WebSocket("ws://insecure.example.invalid/socket");
      wsRef.current.onmessage = (m) => console.log("ws msg:", m.data);
      // MITIGATION: Use wss:// with mutual TLS where appropriate and authenticate messages.
      alert("Opened insecure ws:// (connection attempt).");
    } catch (e) {
      console.warn("WebSocket error", e);
    }
  }

  // --------------------------
  // VULN 12: Dynamically adding third-party script from user input
  // --------------------------
  function injectThirdPartyScript(url) {
    /* VULN 12: inserting <script> with user-supplied src */
    const s = document.createElement("script");
    s.src = url; // user-provided (dangerous)
    document.head.appendChild(s);
    // MITIGATION: Do not load remote scripts from user-provided sources; use CSP and host trusted scripts.
  }

  // --------------------------
  // VULN 13: setTimeout with string (executes via eval)
  // --------------------------
  function unsafeSetTimeout() {
    /* VULN 13: setTimeout with string argument */
    setTimeout("alert('executed string timeout: ' + document.title)", 500);
    // MITIGATION: Pass a function reference to setTimeout instead of a string.
  }

  // --------------------------
  // VULN 14: Exposing stack trace in error messages to user
  // --------------------------
  function throwAndLeakStack() {
    try {
      throw new Error("Demo error with stack");
    } catch (err) {
      /* VULN 14: showing error.stack to user */
      alert("An error occurred: " + err.stack); // leaks implementation details
      // MITIGATION: Log full stack to secure server logs and show generic messages to users.
    }
  }

  // --------------------------
  // VULN 15: Race condition / state update misuse
  // --------------------------
  function incrementRace() {
    /* VULN 15: race condition by relying on stale state (non-functional updates in async loop) */
    // Simulate concurrent-like updates that may lose increments
    for (let i = 0; i < 5; i++) {
      // non-functional update uses stale `counter` captured by closure
      setTimeout(() => {
        setCounter(counter + 1); // incorrect: should use functional updater
      }, i * 10);
    }
    // MITIGATION: Use functional setState: setCounter(c => c + 1) to avoid lost updates.
  }

  // --------------------------
  // Small UI to exercise these vulnerabilities
  // --------------------------
  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: 16 }}>
      <h2>Vulnerable React Demo (15 examples)</h2>

      <section style={{ marginBottom: 12 }}>
        <label>
          User HTML input (VULN 1):
          <textarea
            value={userInput}
            onChange={(e) => setUserInput(e.target.value)}
            rows={3}
            style={{ width: "100%" }}
          />
        </label>
        <DangerousInnerHTML />
      </section>

      <section style={{ marginBottom: 12 }}>
        <label>
          SVG input (VULN 2):
          <input
            value={svgInput}
            onChange={(e) => setSvgInput(e.target.value)}
            style={{ width: "100%" }}
          />
        </label>
        <DangerousSVG />
      </section>

      <section style={{ marginBottom: 12 }}>
        <label>
          Code for eval (VULN 3):
          <input
            value={codeInput}
            onChange={(e) => setCodeInput(e.target.value)}
            style={{ width: "100%" }}
          />
        </label>
        <button onClick={runEval}>Run eval (unsafe)</button>
      </section>

      <section style={{ marginBottom: 12 }}>
        <label>
          Code for new Function (VULN 4):
          <input
            value={funcInput}
            onChange={(e) => setFuncInput(e.target.value)}
            style={{ width: "100%" }}
          />
        </label>
        <button onClick={runNewFunction}>Run new Function (unsafe)</button>
      </section>

      <section style={{ marginBottom: 12 }}>
        <button onClick={generateWeakToken}>Generate weak token (VULN 5)</button>
        <div style={{ marginTop: 6 }}>
          Hardcoded API Key (VULN 6): <strong>{HARD_CODED_API_KEY}</strong>
        </div>
        <div style={{ marginTop: 6 }}>
          <button onClick={storeJwtInLocalStorage}>
            Store JWT in localStorage (VULN 7)
          </button>
        </div>
      </section>

      <section style={{ marginBottom: 12 }}>
        <button onClick={sendCredentialsInUrl}>
          Send credentials in URL (VULN 8)
        </button>{" "}
        <button onClick={() => injectThirdPartyScript("https://cdn.example.invalid/evil.js")}>
          Inject remote script (VULN 12)
        </button>
      </section>

      <section style={{ marginBottom: 12 }}>
        <div>
          <button onClick={handleRedirect}>Trigger unvalidated redirect (VULN 9)</button>
        </div>
        <div style={{ marginTop: 6 }}>
          <button onClick={openInsecureWebSocket}>Open ws:// (VULN 11)</button>
        </div>
        <div style={{ marginTop: 6 }}>
          <button onClick={() => {
            // demonstrate postMessage send (receiver above doesn't validate origin)
            window.postMessage({ hello: "world" }, "*");
            alert("Posted message to window with '*' targetOrigin (VULN 10).");
          }}>
            postMessage '*' (VULN 10)
          </button>
        </div>
      </section>

      <section style={{ marginBottom: 12 }}>
        <button onClick={unsafeSetTimeout}>setTimeout string exec (VULN 13)</button>{" "}
        <button onClick={throwAndLeakStack}>Throw and leak stack (VULN 14)</button>
      </section>

      <section style={{ marginBottom: 12 }}>
        <div>
          <p>Counter (demonstrates VULN 15 race): {counter}</p>
          <button onClick={incrementRace}>Run racey increments (VULN 15)</button>
        </div>
      </section>

      <section style={{ marginBottom: 12 }}>
        <div>
          {/* VULN: insecure cookie storage - written here as demonstration */}
          {/* VULN EXTRA: storing sensitive token in document.cookie (insecure) */}
          <button onClick={() => {
            document.cookie = "session_token=PLAINTEXT_TOKEN; path=/";
            // MITIGATION: Use HttpOnly, Secure cookies set by server; do not set sensitive cookies via JS.
            alert("Wrote token to document.cookie (insecure).");
          }}>
            Write token to document.cookie (insecure)
          </button>
        </div>
      </section>

      <hr />
      <footer style={{ fontSize: 12, color: "#666" }}>
        <p>
          Note: This file intentionally contains insecure patterns for educational purposes only.
          Review the inline MITIGATION comments for each vulnerability.
        </p>
      </footer>
    </div>
  );
}
