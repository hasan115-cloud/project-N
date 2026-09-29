// PhishGuard Content Script v1.4
// Runs on pages — scans links, blocks phishing clicks, shows toasts, plays sound alerts

(function () {
    if (window !== window.top) return; // top frame only

    const PROCESSED   = new WeakSet();
    const urlVerdicts = new Map();   // url → { verdict, score }
    const urlElements = new Map();   // url → Set<element>
    const pendingUrls = new Set();

    let scanDebounce = null;
    let toastRoot = null;
    function getToastRoot() {
        if (!toastRoot || !document.body.contains(toastRoot)) {
            toastRoot = document.createElement("div");
            toastRoot.setAttribute("data-phishguard", "toasts");
            toastRoot.style.cssText =
                "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);z-index:2147483647;" +
                "display:flex;flex-direction:column-reverse;align-items:center;gap:8px;pointer-events:none;";
            document.body.appendChild(toastRoot);
        }
        return toastRoot;
    }

    function showToast(message, type, duration = 5000) {
        const pal = {
            phishing:  { bg:"#7f1d1d", border:"#ef4444", icon:"⛔" },
            suspicious:{ bg:"#78350f", border:"#f59e0b", icon:"⚠️" },
            safe:      { bg:"#14532d", border:"#22c55e", icon:"✅" },
            info:      { bg:"#0e1a2e", border:"#a3a3a3", icon:"🛡" },
        };
        const p = pal[type] || pal.info;
        const t = document.createElement("div");
        t.style.cssText =
            `background:${p.bg};border:1px solid ${p.border};color:#fff;` +
            `padding:10px 14px;border-radius:8px;font-size:13px;` +
            `font-family:'Segoe UI',sans-serif;max-width:300px;` +
            `box-shadow:0 4px 14px rgba(0,0,0,0.5);pointer-events:auto;` +
            `transition:opacity 0.3s ease;line-height:1.4;`;
        t.style.whiteSpace = "pre-line";
        t.textContent = `${p.icon}  ${message}`;
        const x = document.createElement("span");
        x.textContent = " ×";
        x.style.cssText = "cursor:pointer;margin-left:8px;font-weight:700;";
        x.addEventListener("click", () => t.remove());
        t.appendChild(x);
        getToastRoot().appendChild(t);
        setTimeout(() => {
            t.style.opacity = "0";
            setTimeout(() => t.remove(), 320);
        }, duration);
    }

    function showBlockedBadge(el, score) {
        const existing = el.parentNode?.querySelector("[data-phishguard-badge]");
        if (existing) existing.remove();
        const badge = document.createElement("span");
        badge.setAttribute("data-phishguard-badge", "1");
        badge.style.cssText =
            "display:inline-block;background:#dc3545;color:#fff;" +
            "font-size:11px;font-family:'Segoe UI',sans-serif;" +
            "padding:2px 7px;border-radius:4px;margin-left:5px;" +
            "vertical-align:middle;white-space:nowrap;cursor:default;";
        badge.textContent = `⛔ Blocked (${(score * 100).toFixed(0)}% risk)`;
        el.parentNode?.insertBefore(badge, el.nextSibling);
        setTimeout(() => badge.remove(), 5000);
    }

    function safeHost(url) { try { return new URL(url).hostname; } catch { return url; } }

    const PHISHING_THRESHOLD   = 0.60;
    const SUSPICIOUS_THRESHOLD = 0.40;

    function applyVerdict(element, verdict, score) {
        element.classList.remove("phishguard-safe", "phishguard-suspicious", "phishguard-phishing");

        if (verdict === "PHISHING" && score < PHISHING_THRESHOLD) verdict = "SUSPICIOUS";
        if (verdict === "SUSPICIOUS" && score < SUSPICIOUS_THRESHOLD) verdict = "SAFE";

        if (verdict === "PHISHING") {
            element.classList.add("phishguard-phishing");
            element.title = `⚠️ PhishGuard: PHISHING DETECTED (${(score * 100).toFixed(0)}% risk)`;
            element.setAttribute("data-phishguard", "phishing");
            if (!element._pgClickBound) {
                element._pgClickBound = true;
                element.addEventListener("click", function (e) {
                    e.preventDefault(); e.stopImmediatePropagation();
                    showBlockedBadge(element, score);
                    showToast(`⚠ SECURITY ALERT — Phishing link blocked\nURL: ${safeHost(element.href)}\nAction: BLOCKED`, "phishing", 9000);
                    // Notify background to report blocked event
                    chrome.runtime.sendMessage({
                        action: "reportBlockedClick",
                        url: element.href,
                        score: score
                    }).catch(() => {});
                }, { capture: true });
            }
        } else if (verdict === "SUSPICIOUS") {
            element.classList.add("phishguard-suspicious");
            element.title = `⚠️ PhishGuard: Suspicious link (${(score * 100).toFixed(0)}% risk)`;
            element.setAttribute("data-phishguard", "suspicious");
            if (!element._pgClickBound) {
                element._pgClickBound = true;
                element.addEventListener("click", function () {
                    showToast(`Warning: suspicious link — ${safeHost(element.href)}`, "suspicious", 4000);
                }, { capture: true });
            }
        } else if (verdict === "SAFE") {
            element.classList.add("phishguard-safe");
            element.title = "✅ PhishGuard: Safe";
        }
    }

    const pageStats = { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    function recordVerdict(verdict) {
        pageStats.total++;
        if (verdict === "PHISHING")        pageStats.phishing++;
        else if (verdict === "SUSPICIOUS") pageStats.suspicious++;
        else if (verdict === "SAFE")       pageStats.safe++;
        chrome.runtime.sendMessage({ action: "updateStats", stats: pageStats }).catch(() => {});
    }

    function collectNewUrls() {
        const anchors = document.querySelectorAll("a[href]");
        const newUrls = [];
        anchors.forEach(a => {
            if (PROCESSED.has(a)) return;
            const href = a.href;
            if (!href || !href.startsWith("http")) return;
            try { if (new URL(href).hostname === window.location.hostname) return; } catch { return; }
            const text = a.textContent.trim();
            if (text.length === 0 && a.querySelector("img") !== null) { PROCESSED.add(a); return; }
            PROCESSED.add(a);
            if (urlVerdicts.has(href)) {
                const { verdict, score } = urlVerdicts.get(href);
                applyVerdict(a, verdict, score);
                return;
            }
            if (!urlElements.has(href)) { urlElements.set(href, new Set()); newUrls.push(href); }
            urlElements.get(href).add(a);
        });
        return newUrls;
    }

    function scanChunk(urls) {
        return new Promise(resolve => {
            const timer = setTimeout(resolve, 20000);
            chrome.runtime.sendMessage(
                { action: "bulkScan", urls, source: "extension-link" },
                response => {
                    clearTimeout(timer);
                    if (!response?.results) { resolve(); return; }
                    response.results.forEach((result, idx) => {
                        const url     = urls[idx];
                        const verdict = result?.verdict || "ERROR";
                        const score   = result?.score ?? result?.risk_score ?? 0;
                        if (verdict === "ERROR") return;
                        urlVerdicts.set(url, { verdict, score });
                        recordVerdict(verdict);
                        (urlElements.get(url) || new Set()).forEach(el => applyVerdict(el, verdict, score));
                    });
                    resolve();
                }
            );
        });
    }

    async function flushPending() {
        if (pendingUrls.size === 0) return;
        const batch = [...pendingUrls].slice(0, 50);
        pendingUrls.clear();
        const CHUNK = 20;
        for (let i = 0; i < batch.length; i += CHUNK) {
            await scanChunk(batch.slice(i, i + CHUNK));
        }
    }

    function queueScan(urls) {
        urls.forEach(u => pendingUrls.add(u));
        clearTimeout(scanDebounce);
        scanDebounce = setTimeout(flushPending, 500);
    }

    function scanPageLinks() {
        const newUrls = collectNewUrls();
        if (newUrls.length > 0) queueScan(newUrls);
    }

    setTimeout(scanPageLinks, 1500);

    new MutationObserver(() => {
        clearTimeout(window.__pg_rescan);
        window.__pg_rescan = setTimeout(scanPageLinks, 1500);
    }).observe(document.body, { childList: true, subtree: true });

    chrome.runtime.onMessage.addListener(message => {
        if (message.action !== "showScanToast") return;
        const host = safeHost(message.url);
        const { verdict } = message.data || {};
        if (verdict === "PHISHING")        showToast(`PHISHING: ${host}`, "phishing", 6000);
        else if (verdict === "SUSPICIOUS") showToast(`Suspicious: ${host}`, "suspicious", 5000);
        else if (verdict === "SAFE")       showToast(`Safe: ${host}`, "safe", 3000);
        else                               showToast(`Could not scan: ${host}`, "info", 4000);
    });

    console.log("PhishGuard content script active");
})();
