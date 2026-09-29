// PhishGuard warning page script
const params      = new URLSearchParams(window.location.search);
const blockedUrl  = params.get("url") || "";
const score       = parseFloat(params.get("score") || "0");
const verdict     = (params.get("verdict") || "PHISHING").toUpperCase();
const isSuspicious = verdict === "SUSPICIOUS";

let reasons = [];
try { reasons = JSON.parse(decodeURIComponent(params.get("reasons") || "[]")); }
catch { reasons = []; }

if (isSuspicious) {
    document.body.classList.add("suspicious");
    document.title = "PhishGuard — Suspicious Site Warning";
    document.querySelector(".icon").textContent = "⚠️";
    document.querySelector("h1").textContent = "Suspicious Site Warning";
    document.querySelector(".subtitle").textContent =
        "PhishGuard flagged this website as suspicious. It hasn't been " +
        "confirmed malicious, but shows risk signals worth pausing on before you continue.";
}

document.getElementById("blockedUrl").textContent = blockedUrl || "(URL unavailable)";
document.getElementById("scorePill").textContent  = `Risk Score: ${(score * 100).toFixed(1)}%`;

if (Array.isArray(reasons) && reasons.length > 0) {
    document.getElementById("reasonsBlock").style.display = "block";
    const ul = document.getElementById("reasonsList");
    reasons.forEach(r => {
        const li = document.createElement("li");
        li.textContent = String(r);
        ul.appendChild(li);
    });
}

// ── Bottom security-alert toast (dismissible, auto-hides) ───────────────────
(function showAlertToast() {
    if (isSuspicious) return; // warnings get the full-page notice only; the toast is for real blocks
    const rule = params.get("rule") || "";
    const ruleType = params.get("ruleType") || "";
    const action = (params.get("action") || "BLOCKED").toUpperCase();
    let host = blockedUrl;
    try { host = new URL(blockedUrl).hostname; } catch { /* keep raw */ }

    const el = document.createElement("div");
    el.setAttribute("role", "alert");
    el.style.cssText =
        "position:fixed;left:50%;bottom:24px;transform:translate(-50%,40px);opacity:0;z-index:2147483647;" +
        "width:min(520px,calc(100vw - 32px));background:#7f1d1d;border:1px solid #ef4444;color:#fff;" +
        "border-radius:12px;padding:14px 44px 14px 16px;box-shadow:0 10px 40px rgba(0,0,0,.6);" +
        "font:13px/1.5 'Segoe UI',system-ui,sans-serif;transition:transform .35s ease,opacity .35s ease;";
    const title = document.createElement("div");
    title.style.cssText = "font-weight:800;letter-spacing:.04em;margin-bottom:4px;";
    title.textContent = "⚠ SECURITY ALERT";
    const kind = document.createElement("div");
    kind.style.cssText = "font-weight:600;";
    kind.textContent = ruleType === "PHISHING" ? "Phishing/Blacklist Rule Triggered" : "Phishing Threat Detected";
    const lines = document.createElement("div");
    lines.style.cssText = "opacity:.95;word-break:break-all;";
    const add = (label, value) => {
        const d = document.createElement("div");
        d.textContent = `${label}: ${value}`;
        lines.appendChild(d);
    };
    add("URL", host);
    if (rule) add("Matched Rule", rule);
    add("Action", action);
    const close = document.createElement("button");
    close.textContent = "×";
    close.setAttribute("aria-label", "Dismiss alert");
    close.style.cssText = "position:absolute;top:8px;right:10px;background:none;border:none;color:#fff;font-size:22px;cursor:pointer;line-height:1;";
    const hide = () => { el.style.opacity = "0"; el.style.transform = "translate(-50%,40px)"; setTimeout(() => el.remove(), 400); };
    close.addEventListener("click", hide);
    el.append(title, kind, lines, close);
    document.body.appendChild(el);
    requestAnimationFrame(() => { el.style.opacity = "1"; el.style.transform = "translate(-50%,0)"; });
    setTimeout(hide, 15000);
})();

function goBack() {
    if (history.length > 1) history.back();
    else window.location.href = "https://www.google.com";
}

function proceedAnyway() {
    if (!blockedUrl) return;
    const confirmMsg = isSuspicious
        ? "⚠️ Caution\n\nThis site shows suspicious characteristics but has not been confirmed malicious.\n\nProceed anyway?"
        : "⚠️ Warning\n\nThis site is very likely to steal your credentials or install malware.\n\nAre you absolutely sure you want to proceed?";
    const confirmed = confirm(confirmMsg);
    if (!confirmed) return;
    chrome.runtime.sendMessage({ action: "bypassUrl", url: blockedUrl }, () => {
        window.location.href = blockedUrl;
    });
}

document.getElementById("btnBack").addEventListener("click", goBack);
document.getElementById("btnProceed").addEventListener("click", proceedAnyway);
