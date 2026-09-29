// Plays PhishGuard's audible alarm. Lives in an offscreen document because a
// service worker has no audio, and a normal page would need a user gesture.
let ctx = null;

function siren() {
    ctx = ctx || new (self.AudioContext || self.webkitAudioContext)();
    if (ctx.state === "suspended") ctx.resume().catch(() => {});
    const t0 = ctx.currentTime + 0.02;
    // Two-tone siren, ~2.4 s: unmistakable, not a "ding" that can be missed.
    for (let i = 0; i < 6; i++) {
        const start = t0 + i * 0.4;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "square";
        osc.frequency.setValueAtTime(i % 2 === 0 ? 960 : 640, start);
        gain.gain.setValueAtTime(0.0001, start);
        gain.gain.exponentialRampToValueAtTime(0.35, start + 0.03);
        gain.gain.setValueAtTime(0.35, start + 0.32);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + 0.38);
        osc.connect(gain); gain.connect(ctx.destination);
        osc.start(start); osc.stop(start + 0.4);
    }
}

chrome.runtime.onMessage.addListener(msg => {
    if (msg && msg.target === "pg-offscreen" && msg.type === "play-alarm") {
        try { siren(); } catch (e) { console.warn("PhishGuard alarm failed:", e); }
    }
});
