// PhishGuard Gmail/Outlook Content Script
(function () {
    if (window !== window.top) return;

    const processed  = new WeakSet();
    const verdictMap = new Map();

    function safeHost(url) {
        try { return new URL(url).hostname; } catch { return url; }
    }

    function applyEmailVerdict(a, verdict, score) {
        if (verdict === "PHISHING") {
            a.style.cssText += "color:#ff6b7a!important;text-decoration:line-through!important;";
            a.title = `⛔ PhishGuard: PHISHING (${(score*100).toFixed(0)}% risk) — ${safeHost(a.href)}`;
            if (!a._pgEmail) {
                a._pgEmail = true;
                a.addEventListener("click", e => {
                    e.preventDefault();
                    e.stopImmediatePropagation();
                    if (confirm(`⛔ PhishGuard blocked this link.\n\nURL: ${a.href}\n\nThis is identified as a dangerous phishing link. Proceed anyway?`)) {
                        window.open(a.href, "_blank", "noopener,noreferrer");
                    }
                }, { capture: true });
            }
        } else if (verdict === "SUSPICIOUS") {
            a.style.cssText += "color:#f59e0b!important;border-bottom:2px dashed #f59e0b!important;";
            a.title = `⚠️ PhishGuard: Suspicious (${(score*100).toFixed(0)}% risk) — ${safeHost(a.href)}`;
        }
    }

    function scanBatch(urls) {
        return new Promise(resolve => {
            chrome.runtime.sendMessage({ action: "bulkScan", urls, source: "gmail-content" }, res => {
                if (res?.results) {
                    res.results.forEach((r, i) => {
                        if (r && r.verdict && r.verdict !== "ERROR") {
                            verdictMap.set(urls[i], { verdict: r.verdict, score: r.score ?? r.risk_score ?? 0 });
                        }
                    });
                }
                resolve();
            });
        });
    }

    function collectEmailLinks() {
        const selectors = [
            ".a3s.aiL a[href]",
            "[data-message-id] a[href]",
            ".ReadMsgBody a[href]",
            "[data-content-type] a[href]"
        ];

        const anchors = [];
        selectors.forEach(sel => {
            try { anchors.push(...document.querySelectorAll(sel)); } catch { }
        });

        const newUrls = [];
        anchors.forEach(a => {
            if (processed.has(a)) return;
            const href = a.href;
            if (!href || !href.startsWith("http")) return;
            processed.add(a);

            if (verdictMap.has(href)) {
                const { verdict, score } = verdictMap.get(href);
                applyEmailVerdict(a, verdict, score);
                return;
            }
            newUrls.push(href);
        });

        return [...new Set(newUrls)];
    }

    async function scanEmailLinks() {
        const urls = collectEmailLinks();
        if (urls.length === 0) return;

        for (let i = 0; i < urls.length; i += 20) {
            const chunk = urls.slice(i, i + 20);
            await scanBatch(chunk);
            document.querySelectorAll("a[href]").forEach(a => {
                if (!processed.has(a)) return;
                const v = verdictMap.get(a.href);
                if (v) applyEmailVerdict(a, v.verdict, v.score);
            });
        }
    }

    setTimeout(scanEmailLinks, 2000);

    new MutationObserver(() => {
        clearTimeout(window.__pg_email_rescan);
        window.__pg_email_rescan = setTimeout(scanEmailLinks, 1500);
    }).observe(document.body, { childList: true, subtree: true });

    console.log("PhishGuard email scanner active");
})();
