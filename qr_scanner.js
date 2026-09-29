// PhishGuard QR Code Scanner
(function () {
    if (window !== window.top) return;

    const scannedQRs = new Set();

    function getToastRoot() {
        let r = document.getElementById("__pg_qr_toasts");
        if (!r) {
            r = document.createElement("div");
            r.id = "__pg_qr_toasts";
            r.style.cssText = "position:fixed;bottom:18px;right:18px;z-index:2147483647;display:flex;flex-direction:column;gap:8px;";
            document.body.appendChild(r);
        }
        return r;
    }

    function showQRToast(message, type) {
        const colors = {
            phishing:  { bg:"#7f1d1d", border:"#ef4444" },
            suspicious:{ bg:"#78350f", border:"#f59e0b" },
            safe:      { bg:"#14532d", border:"#22c55e" },
        };
        const c = colors[type] || colors.safe;
        const t = document.createElement("div");
        t.style.cssText = `background:${c.bg};border:1px solid ${c.border};color:#fff;padding:10px 14px;border-radius:8px;font-size:13px;font-family:'Segoe UI',sans-serif;max-width:320px;box-shadow:0 4px 14px rgba(0,0,0,0.5);`;
        t.textContent = message;
        getToastRoot().appendChild(t);
        setTimeout(() => { t.style.opacity="0"; t.style.transition="opacity 0.3s"; setTimeout(() => t.remove(), 320); }, 6000);
    }

    async function decodeQRImage(imgEl) {
        return new Promise(resolve => {
            try {
                const canvas = document.createElement("canvas");
                const SIZE = 300;
                canvas.width = SIZE;
                canvas.height = SIZE;
                const ctx = canvas.getContext("2d");
                const tmp = new Image();
                tmp.crossOrigin = "anonymous";
                tmp.onload = () => {
                    try {
                        ctx.drawImage(tmp, 0, 0, SIZE, SIZE);
                        const imageData = ctx.getImageData(0, 0, SIZE, SIZE);
                        if (typeof jsQR === "function") {
                            const result = jsQR(imageData.data, SIZE, SIZE);
                            resolve(result ? result.data : null);
                        } else {
                            resolve(null);
                        }
                    } catch {
                        resolve(null);
                    }
                };
                tmp.onerror = () => resolve(null);
                tmp.src = imgEl.src;
            } catch {
                resolve(null);
            }
        });
    }

    async function scanQRUrl(url) {
        chrome.runtime.sendMessage({ action: "scan", url, source: "extension-qr" }, data => {
            if (!data) return;
            try {
                const host = new URL(url).hostname;
                if (data.verdict === "PHISHING") {
                    showQRToast(`⛔ QR code leads to PHISHING site!\n${host}`, "phishing");
                } else if (data.verdict === "SUSPICIOUS") {
                    showQRToast(`⚠️ QR code leads to suspicious site: ${host}`, "suspicious");
                } else if (data.verdict === "SAFE") {
                    showQRToast(`✅ QR code → ${host} (Safe)`, "safe");
                }
            } catch { }
        });
    }

    async function processImages() {
        if (typeof jsQR !== "function") return;
        const imgs = document.querySelectorAll("img[src]");
        for (const img of imgs) {
            if (scannedQRs.has(img.src)) continue;
            const w = img.naturalWidth || img.width;
            const h = img.naturalHeight || img.height;
            if (w < 50 || h < 50) continue;
            const ratio = w / h;
            if (ratio < 0.7 || ratio > 1.4) continue;

            scannedQRs.add(img.src);
            const decoded = await decodeQRImage(img);
            if (decoded && decoded.startsWith("http")) {
                await scanQRUrl(decoded);
            }
        }
    }

    setTimeout(processImages, 3000);

    new MutationObserver(() => {
        clearTimeout(window.__pg_qr_rescan);
        window.__pg_qr_rescan = setTimeout(processImages, 2000);
    }).observe(document.body, { childList: true, subtree: true });
})();
