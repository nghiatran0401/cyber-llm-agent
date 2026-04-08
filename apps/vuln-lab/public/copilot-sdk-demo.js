/**
 * Demo "3rd-party SDK" for Cyber LLM Copilot.
 *
 * Simulates a merchant site that added our package and a script tag: the SDK polls
 * the same dashboard API the lab exposes and fires window.alert() when NEW attack
 * rows appear (after this script loaded). No npm build step — drop-in like a CDN snippet.
 */
(function copilotSdkDemo() {
  var POLL_MS = 2800;
  var seen = Object.create(null);
  var primed = false;

  function poll() {
    fetch("/api/dashboard/system-logs?limit=40&attack_only=true&_=" + Date.now(), {
      cache: "no-store",
      credentials: "same-origin",
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        if (!data || !data.ok || !Array.isArray(data.result)) {
          return;
        }
        var entries = data.result;
        if (!primed) {
          for (var i = 0; i < entries.length; i += 1) {
            var e = entries[i];
            if (e && e.attackDetected && e.requestId) {
              seen[e.requestId] = true;
            }
          }
          primed = true;
          return;
        }
        for (var j = 0; j < entries.length; j += 1) {
          var row = entries[j];
          if (!row || !row.attackDetected || !row.requestId) {
            continue;
          }
          if (seen[row.requestId]) {
            continue;
          }
          seen[row.requestId] = true;
          var lines = [
            "[Cyber LLM Copilot — browser SDK demo]",
            "",
            "Your site just handled a request we classify as suspicious.",
            "",
            "Risk hint: " + (row.riskHint || "unknown"),
            "Scenario: " + (row.scenarioId || "n/a"),
            (row.method || "?") + " " + (row.path || ""),
            "",
            "In production this would come from your npm package + init snippet,",
            "not from polling — this file only mimics the end-user alert.",
          ];
          window.alert(lines.join("\n"));
        }
      })
      .catch(function () {
        /* Demo SDK: stay quiet on network errors */
      });
  }

  poll();
  setInterval(poll, POLL_MS);
})();
