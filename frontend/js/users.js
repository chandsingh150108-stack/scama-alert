document.addEventListener("DOMContentLoaded", async function () {
  const board = document.getElementById("board");
  if (!board) return;
  const { data } = await window.App.api("/api/users?limit=20");
  const rows = (data && data.users) || [];
  board.innerHTML = '<table class="tbl"><tr><th>#</th><th>User</th><th>Role</th><th>Tier</th><th>Score</th><th>Reports</th><th>Accuracy</th></tr>' +
    rows.map(function (u, i) {
      return "<tr><td>" + (i + 1) + '</td><td><a href="/users/' + encodeURIComponent(u.user_id || u.id || "") + '">' +
        window.App.escapeHtml(u.name || "") + "</a></td><td>" + window.App.escapeHtml(u.role || "") + "</td><td>" +
        window.App.tierPill(u.reputation_tier) + "</td><td>" + (u.reputation_score || 0) + "</td><td>" +
        (u.total_reports || 0) + "</td><td>" + (u.accuracy_rate != null ? Number(u.accuracy_rate).toFixed(1) + "%" : "—") + "</td></tr>";
    }).join("") + "</table>";
});
