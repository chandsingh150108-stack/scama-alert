function uid() {
  const m = window.location.pathname.match(/\/users\/([^\/\.]+)/);
  if (m) return decodeURIComponent(m[1]);
  return new URLSearchParams(window.location.search).get("id");
}
document.addEventListener("DOMContentLoaded", async function () {
  const id = uid();
  const box = document.getElementById("profile");
  const { ok, data } = await window.App.api("/api/users/" + encodeURIComponent(id));
  if (!ok || !data || !data.user) { box.innerHTML = '<div class="card">User not found</div>'; return; }
  const u = data.user;
  const reports = data.reports || [];
  const events = data.reputationEvents || [];
  box.innerHTML = "<h1>" + window.App.escapeHtml(u.name || "") + "</h1>" +
    "<div>" + window.App.tierPill(u.reputation_tier) + " score " + (u.reputation_score || 0) + "</div>" +
    '<div class="card"><strong>' + (u.total_reports || 0) + "</strong> reports &middot; <strong>" +
    (u.verified_reports || 0) + "</strong> verified &middot; <strong>" + (u.total_votes_cast || 0) +
    "</strong> votes</div>" +
    "<h3>Recent reports</h3>" + (reports.length === 0 ? '<div class="card muted">No reports yet</div>' :
      reports.map(function (r) {
        return '<div class="card"><a href="/reports/' + encodeURIComponent(r.id) + '">' + window.App.escapeHtml(r.title) + "</a></div>";
      }).join("")) +
    "<h3>Reputation history</h3>" + (events.length === 0 ? '<div class="card muted">No reputation events yet</div>' :
      events.map(function (e) {
        const d = Number(e.delta || 0);
        const color = d >= 0 ? "green" : "red";
        return '<div class="card small"><strong style="color:' + color + '">' + (d >= 0 ? "+" : "") + d + "</strong> " +
          window.App.escapeHtml(e.reason || "") + " — " + window.App.fmtDateEnIN(e.created_at) + "</div>";
      }).join(""));
});
