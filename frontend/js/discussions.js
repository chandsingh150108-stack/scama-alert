document.addEventListener("DOMContentLoaded", async function () {
  const box = document.getElementById("list");
  if (!box) return;
  const { data } = await window.App.api("/api/discussions?limit=20");
  const rows = (data && data.discussions) || [];
  box.innerHTML = rows.length === 0 ? '<div class="card muted">No discussions yet.</div>' : rows.map(function (d) {
    const score = (d.upvotes || 0) - (d.downvotes || 0);
    return '<div class="card"><div class="small muted">' + window.App.escapeHtml(d.domain || "") + " " +
      (d.is_pinned ? "<strong>Pinned</strong> " : "") + (d.is_locked ? "<strong>Locked</strong>" : "") + "</div>" +
      '<a href="/discussions/' + encodeURIComponent(d.id) + '"><strong>' + window.App.escapeHtml(d.title) + "</strong></a>" +
      '<div class="small muted">' + window.App.escapeHtml(d.author_name || "") + " &middot; " + (d.reply_count || 0) +
      " replies &middot; " + score + " votes</div></div>";
  }).join("");
});
