/* Shared utils. Mirrors src/lib/utils.ts client parts (no hardcoded host). */
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  return { ok: res.ok, status: res.status, data };
}
function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}
function getTimeAgo(dateStr) {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMins = Math.floor((now - date) / 60000);
  if (!(diffMins >= 0)) return "";
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return diffMins + "m ago";
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return diffHours + "h ago";
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return diffDays + "d ago";
  return date.toLocaleDateString("en-IN");
}
function tierPill(tier) {
  const t = tier || "newcomer";
  return '<span class="pill ' + escapeHtml(t) + '">' + escapeHtml(t) + "</span>";
}
function riskPill(level, score, variant) {
  const lv = (level || "other").toLowerCase();
  const cls = ["critical", "high", "medium", "low", "safe"].indexOf(lv) >= 0 ? lv : "other";
  const label = (score != null ? Number(score).toFixed(1) + " " : "") + lv.toUpperCase();
  return '<span class="pill ' + cls + '">' + escapeHtml(label) + "</span>";
}
function fmtDateEnIN(s) {
  try { return new Date(s).toLocaleDateString("en-IN"); } catch (e) { return String(s || ""); }
}
function reportCard(r) {
  const score = (r.confirm_votes || 0) - (r.deny_votes || 0);
  const tags = (r.tags || "").split(", ").filter(Boolean).map(function (t) {
    return '<span class="tag">' + escapeHtml(t) + "</span>";
  }).join("");

  const thumbHtml = r.thumbnail_url
    ? '<a href="/reports/' + encodeURIComponent(r.report_id) + '" class="report-thumb-link">' +
      '<img src="' + encodeURI(r.thumbnail_url) + '" alt="' + escapeHtml(r.title) + '" loading="lazy" class="report-card-thumb">' +
      '</a>'
    : '';

  const amountHtml = r.amount_lost
    ? '<span class="amount-pill">₹' + Number(r.amount_lost).toLocaleString("en-IN") + ' lost</span>'
    : '';

  const stage = (r.verification_stage || "").toLowerCase();
  const stageLabels = {
    "confirmed_malicious": "Confirmed Scam",
    "community_verified": "Community Verified",
    "multiple_reports": "Multiple Reports",
    "under_review": "Under Review",
    "reported": "Reported"
  };
  const stageHtml = stage
    ? '<span class="stage-pill ' + escapeHtml(stage) + '">' + escapeHtml(stageLabels[stage] || stage) + '</span>'
    : '';

  return '<div class="card report-card-item">' +
    '<div class="report-row">' +
      '<div class="vote-rail">' +
        '<span>&#9650;</span>' +
        '<strong>' + score + '</strong>' +
        '<span>&#9660;</span>' +
      '</div>' +
      '<div class="report-body" style="flex:1;min-width:0">' +
        '<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:0.75rem;margin-bottom:0.25rem">' +
          '<a href="/reports/' + encodeURIComponent(r.report_id) + '" class="report-title">' + escapeHtml(r.title) + '</a>' +
          amountHtml +
        '</div>' +
        '<div class="small muted" style="margin-bottom:0.35rem">' +
          escapeHtml(r.reporter_name || "anonymous") + ' ' + tierPill(r.reporter_tier) +
          ' &middot; <strong style="color:var(--text)">' + escapeHtml(r.category_name || "") + '</strong>' +
          ' &middot; <span style="font-family:monospace">' + escapeHtml(r.domain || "") + '</span> ' + riskPill(r.website_risk_level) +
          (stageHtml ? ' ' + stageHtml : '') +
        '</div>' +
        '<div class="small muted" style="margin-bottom:0.4rem">' +
          getTimeAgo(r.reported_at) + ' &middot; ' + (r.total_votes || 0) + ' votes &middot; ' + (r.evidence_count || 0) + ' evidence' +
        '</div>' +
        '<div>' + tags + '</div>' +
      '</div>' +
      (thumbHtml ? '<div class="report-thumb-box">' + thumbHtml + '</div>' : '') +
    '</div>' +
  '</div>';
}
window.App = { api, escapeHtml, getTimeAgo, tierPill, riskPill, fmtDateEnIN, reportCard };
