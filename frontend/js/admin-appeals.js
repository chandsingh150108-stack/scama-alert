document.addEventListener("DOMContentLoaded", async function () {
  const box = document.getElementById("box");
  const me = await window.App.api("/api/me");
  if (!me.ok) { box.innerHTML = '<div class="card">Loading…</div>'; return; }
  const r = await window.App.api("/api/admin/appeals");
  if (!r.ok) { box.innerHTML = '<div class="error">' + window.App.escapeHtml((r.data && r.data.error) || "Forbidden") + "</div>"; return; }
  let rows = r.data.appeals || [];
  if (!rows.length) { box.innerHTML = '<div class="card muted">No appeals found.</div>'; return; }
  function badge(s) {
    const c = s === "pending" ? "medium" : (s === "upheld" ? "safe" : (s === "overturned" ? "critical" : "other"));
    return '<span class="pill ' + c + '">' + window.App.escapeHtml(s || "") + "</span>";
  }
  function render() {
    box.innerHTML = '<table class="tbl"><tr><th>Appeal</th><th>Status</th><th>Actions</th></tr>' + rows.map(function (a, i) {
      const actions = (a.appeal_status === "pending")
        ? '<button data-i="' + i + '" data-s="upheld" class="btn green">Uphold</button> <button data-i="' + i + '" data-s="overturned" class="btn red">Overturn</button> <button data-i="' + i + '" data-s="rejected" class="btn gray">Reject</button>'
        : "Resolved";
      return "<tr><td>" + window.App.escapeHtml(a.report_title || a.appeal_id || a.id || "") + "</td><td>" + badge(a.appeal_status) + "</td><td>" + actions + "</td></tr>";
    }).join("") + "</table>";
    box.querySelectorAll("button[data-i]").forEach(function (b) {
      b.onclick = async function () {
        const a = rows[Number(b.getAttribute("data-i"))];
        b.disabled = true;
        const res = await window.App.api("/api/admin/appeals", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ appeal_id: a.appeal_id || a.id, new_status: b.getAttribute("data-s") }) });
        if (res.ok) { a.appeal_status = b.getAttribute("data-s"); render(); }
        else { alert((res.data && res.data.error) || "Failed"); b.disabled = false; }
      };
    });
  }
  render();
});
