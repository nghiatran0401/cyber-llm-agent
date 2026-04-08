/**
 * Count failed auth attempts per IP in a sliding window.
 * Single wrong passwords are normal user error; brute-force-style signal only after threshold.
 */
const BRUTE_FORCE_THRESHOLD = Number(process.env.LAB_BRUTE_FORCE_THRESHOLD || 3);
const BRUTE_FORCE_WINDOW_MS = Number(process.env.LAB_BRUTE_FORCE_WINDOW_MS || 10 * 60 * 1000);

const timestampsByIp = new Map();

function recordFailedAttempt(ip) {
  const key = String(ip || "127.0.0.1");
  const now = Date.now();
  let times = timestampsByIp.get(key) || [];
  times = times.filter((t) => now - t < BRUTE_FORCE_WINDOW_MS);
  times.push(now);
  timestampsByIp.set(key, times);
  return {
    countInWindow: times.length,
    threshold: BRUTE_FORCE_THRESHOLD,
    windowMs: BRUTE_FORCE_WINDOW_MS,
  };
}

function clearIp(ip) {
  if (ip === undefined || ip === null) {
    timestampsByIp.clear();
    return;
  }
  timestampsByIp.delete(String(ip));
}

module.exports = {
  recordFailedAttempt,
  clearIp,
  BRUTE_FORCE_THRESHOLD,
  BRUTE_FORCE_WINDOW_MS,
};
