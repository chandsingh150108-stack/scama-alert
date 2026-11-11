document.addEventListener("DOMContentLoaded", async function () {
  const box = document.getElementById("box");
  const me = await window.App.api("/api/me");
  if (!me.ok) { box.innerHTML = '<div class="card">Loading…</div>'; return; }
  async function load() {
    const r = await window.App.api("/api/admin/reports?limit=50");
    if (!r.ok) { box.innerHTML = '<div class="error">' + window.App.escapeHtml((r.data && r.data.error) || "Forbidden") + "</div>"; return; }
    const rows = r.data.reports || [];
    if (!rows.length) { box.innerHTML = '<div class="card muted">No pending reports.</div>'; return; }
    box.innerHTML = '<p><button class="btn green" id="approve-all">Approve All (' + rows.length + ')</button> ' +
      '<button class="btn gray" id="archive-all">Archive All (' + rows.length + ")</button></p>" +
      '<table class="tbl"><tr><th>Report</th><th>Category</th><th>Reporter</th><th>Website</th><th>Waiting (hrs)</th></tr>' +
      rows.map(function (x) {
        return "<tr><td><a href='/reports/" + encodeURIComponent(x.report_id || x.id || "") + "'>" +
          window.App.escapeHtml(x.title || "") + "</a></td><td>" + window.App.escapeHtml(x.category_name || "") +
          "</td><td>" + window.App.escapeHtml(x.reporter_name || "") + "</td><td>" + window.App.escapeHtml(x.domain || "") +
          "</td><td>" + Math.round(x.hours_waiting || 0) + "</td></tr>";
      }).join("") + "</table>";
    async function bulk(status) {
      const ids = rows.map(function (x) { return x.report_id || x.id; });
      const res = await window.App.api("/api/admin/reports", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ report_ids: ids, status }) });
      if (res.ok) load(); else alert((res.data && res.data.error) || "Failed");
    }
    document.getElementById("approve-all").onclick = function () { bulk("active"); };
    document.getElementById("archive-all").onclick = function () { bulk("archived"); };
  }
  load();
});
