function did() {
  const m = window.location.pathname.match(/\/discussions\/([^\/\.]+)/);
  if (m) return decodeURIComponent(m[1]);
  return new URLSearchParams(window.location.search).get("id");
}
function tierColor(t) {
  if (t === "moderator") return "background:#fee2e2;color:#b91c1c";
  if (t === "expert") return "background:#ffedd5;color:#c2410c";
  return "background:#ffedd5;color:#9a3412";
}
document.addEventListener("DOMContentLoaded", async function () {
  const id = did();
  const box = document.getElementById("thread");
  const { data } = await window.App.api("/api/discussions/" + encodeURIComponent(id) + "/replies");
  const rows = (data && data.replies) || [];
  if (!rows.length) { box.innerHTML = '<div class="card muted">No replies yet.</div>'; return; }
  box.innerHTML = rows.map(function (r) {
    const score = (r.upvotes || 0) - (r.downvotes || 0);
    var tierCls = r.author_tier === "moderator" ? "tier-moderator" : (r.author_tier === "expert" ? "tier-expert" : "tier-other");
    return '<div class="card" style="margin-left:' + ((r.depth || 0) * 24) + 'px"><span class="pill ' + tierCls + '" style="' +
      tierColor(r.author_tier) + '">' + window.App.escapeHtml(r.author_tier || "newcomer") + "</span> " +
      window.App.escapeHtml(r.author_name || "") + '<p>' + window.App.escapeHtml(r.body || "") + "</p>" +
      '<div class="small muted">' + score + " votes &middot; " + window.App.fmtDateEnIN(r.created_at) +
      ' &middot; <button class="btn gray">Reply</button></div></div>';
  }).join("");
});
