document.addEventListener("DOMContentLoaded", async function () {
  const q = new URLSearchParams(window.location.search).get("q") || "";
  document.getElementById("q").value = q;
  const meta = document.getElementById("meta");
  const box = document.getElementById("results");
  if (!q) { meta.textContent = ""; box.innerHTML = '<div class="muted">Enter a search query above and press Search…</div>'; return; }
  const { data } = await window.App.api("/api/search?q=" + encodeURIComponent(q));
  const results = (data && data.results) || [];
  meta.textContent = results.length + " result(s) for \"" + q + "\"";
  box.innerHTML = results.length === 0 ? '<div class="card muted">No results found…</div>' : results.map(function (r) {
    return window.App.reportCard({
      report_id: r.id, title: r.title, reporter_name: r.reporter_name, reporter_tier: "trusted",
      category_name: r.category_name, category_slug: "", domain: r.domain,
      website_risk_level: r.risk_level, confirm_votes: 0, deny_votes: 0, total_votes: 0,
      evidence_count: 0, reported_at: r.created_at, tags: "",
    });
  }).join("");
});
