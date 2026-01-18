const AGENT_URL = "http://127.0.0.1:9090";

let activeToken = localStorage.getItem("safeauth_session_token") || "";

const el = (id) => document.getElementById(id);

function logEvent(msg) {
  const box = el("event-log");
  const ts = new Date().toLocaleTimeString();
  box.textContent += `\n[${ts}] ${msg}`;
  box.scrollTop = box.scrollHeight;
}

function shortKey(k) {
  if (!k || k.length < 18) return k || "";
  return k.slice(0, 10) + "..." + k.slice(-8);
}

async function checkServer() {
  try {
    const res = await fetch("/health");
    const data = await res.json();
    if (res.ok) {
      el("server-pill").textContent = `Server: ${data.origin}`;
      el("server-pill").className = "pill pill-ok";
    }
  } catch {
    el("server-pill").textContent = "Server: unreachable";
    el("server-pill").className = "pill pill-warn";
  }
}

async function checkAgent() {
  try {
    const res = await fetch(`${AGENT_URL}/status`);
    if (!res.ok) throw new Error("not ok");
    const data = await res.json();
    el("agent-pill").textContent = "Local Agent: connected";
    el("agent-pill").className = "pill pill-ok";

    el("agent-info").classList.remove("hidden");
    el("agent-acct").textContent = data.account_id;
    el("agent-origin").textContent = data.origin;
    el("agent-epoch").textContent = String(data.epoch);
    el("agent-pub").textContent = data.public_key;

    ["btn-register", "btn-login", "btn-rotate", "btn-anon"].forEach((id) => {
      el(id).disabled = false;
    });
  } catch {
    el("agent-pill").textContent = "Local Agent: offline";
    el("agent-pill").className = "pill pill-warn";
    el("agent-info").classList.add("hidden");
    ["btn-register", "btn-login", "btn-rotate", "btn-anon"].forEach((id) => {
      el(id).disabled = true;
    });
  }
}

async function refreshAccounts() {
  try {
    const res = await fetch("/accounts");
    const data = await res.json();
    const tbody = el("accounts-tbody");
    const list = data.accounts || [];
    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="muted center">No accounts registered yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = list
      .map(
        (a) => `
      <tr>
        <td class="mono">${a.account_id}</td>
        <td class="mono" title="${a.public_key}">${shortKey(a.public_key)}</td>
        <td class="mono" title="${a.recovery_public_key}">${shortKey(a.recovery_public_key)}</td>
        <td class="mono">${a.epoch}</td>
        <td class="mono">${a.created_at}</td>
      </tr>`
      )
      .join("");
  } catch (err) {
    logEvent(`Failed to load accounts: ${err.message}`);
  }
}

async function verifyCurrentSession() {
  if (!activeToken) {
    renderSignedOut();
    return;
  }
  try {
    const res = await fetch("/session", {
      headers: { Authorization: `Bearer ${activeToken}` },
    });
    const data = await res.json();
    if (!res.ok) {
      logEvent(`Session invalid/expired: ${data.error || res.status}`);
      renderSignedOut();
      return;
    }
    el("signed-out-view").classList.add("hidden");
    el("signed-in-view").classList.remove("hidden");
    el("auth-mode-badge").textContent = data.anonymous ? "Anonymous Ring Member" : "Authenticated";
    el("auth-mode-badge").className = "badge badge-ok";
    el("session-pill").textContent = data.anonymous ? "Session: anonymous" : `Session: ${data.sub.slice(0, 10)}...`;
    el("session-pill").className = "pill pill-ok";

    el("claim-sub").textContent = data.sub;
    el("claim-origin").textContent = data.origin;
    el("claim-anon").textContent = String(Boolean(data.anonymous));
    el("claim-jti").textContent = data.jti;
    el("claim-exp").textContent = new Date(data.exp * 1000).toLocaleString();
    el("token-input").value = activeToken;
  } catch (err) {
    logEvent(`Session check error: ${err.message}`);
  }
}

function renderSignedOut() {
  el("signed-out-view").classList.remove("hidden");
  el("signed-in-view").classList.add("hidden");
  el("auth-mode-badge").textContent = "Locked";
  el("auth-mode-badge").className = "badge badge-muted";
  el("session-pill").textContent = "Session: signed out";
  el("session-pill").className = "pill pill-neutral";
}

async function runAgentAction(path, label) {
  logEvent(`-> ${label}...`);
  try {
    const res = await fetch(`${AGENT_URL}${path}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) {
      logEvent(`!! ${label} failed: ${data.error || res.status}`);
      return;
    }
    logEvent(`OK ${label}: ${JSON.stringify(data)}`);
    if (data.session_token) {
      activeToken = data.session_token;
      localStorage.setItem("safeauth_session_token", activeToken);
    }
    await checkAgent();
    await refreshAccounts();
    await verifyCurrentSession();
  } catch (err) {
    logEvent(`!! ${label} error: ${err.message}`);
  }
}

el("btn-register").addEventListener("click", () => runAgentAction("/action/register", "Register Account"));
el("btn-login").addEventListener("click", () => runAgentAction("/action/login", "Ed25519 Challenge-Response Login"));
el("btn-rotate").addEventListener("click", () => runAgentAction("/action/rotate", "Key Rotation (Recovery Key)"));
el("btn-anon").addEventListener("click", () => runAgentAction("/action/anon-login", "Anonymous 1-of-N Ring Login"));

el("btn-verify-token").addEventListener("click", async () => {
  activeToken = el("token-input").value.trim();
  if (activeToken) {
    localStorage.setItem("safeauth_session_token", activeToken);
  }
  await verifyCurrentSession();
});

el("btn-refresh-session").addEventListener("click", verifyCurrentSession);
el("btn-logout").addEventListener("click", () => {
  activeToken = "";
  localStorage.removeItem("safeauth_session_token");
  el("token-input").value = "";
  renderSignedOut();
  logEvent("Cleared local session token.");
});

el("btn-refresh-accounts").addEventListener("click", refreshAccounts);
el("btn-clear-log").addEventListener("click", () => {
  el("event-log").textContent = "Log cleared.";
});

(async () => {
  await checkServer();
  await checkAgent();
  await refreshAccounts();
  await verifyCurrentSession();
  setInterval(checkAgent, 4000);
})();
