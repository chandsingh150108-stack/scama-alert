function wid() {
  const m = window.location.pathname.match(/\/websites\/([^\/\.]+)/);
  if (m) return decodeURIComponent(m[1]);
  return new URLSearchParams(window.location.search).get("id");
}
document.addEventListener("DOMContentLoaded", async function () {
  const id = wid();
  const box = document.getElementById("site");
  const { ok, data } = await window.App.api("/api/websites/" + encodeURIComponent(id));
  if (!ok || !data || !data.website) { box.innerHTML = '<div class="card">Website not found</div>'; return; }
  const w = data.website;
  const rb = data.riskBreakdown || {};
  function yn(v) { return v ? '<strong style="color:green">Yes</strong>' : '<strong style="color:red">No</strong>'; }
  function bar(v) {
    const n = v == null ? null : Number(v);
    return (n == null ? "N/A" : n.toFixed(1)) + '<div class="bar orange"><div style="width:' + (n == null ? 0 : n) + '%"></div></div>';
  }
  box.innerHTML = "<h1>" + window.App.escapeHtml(w.domain || "") + "</h1>" +
    "<div>" + window.App.riskPill(w.risk_level, w.risk_score) + "</div>" +
    '<div class="card"><h3>Community sub-score</h3>' + bar(rb.community_sub_score != null ? rb.community_sub_score : w.community_sub_score) + "</div>" +
    '<div class="card"><h3>Automated sub-score</h3>' + bar(rb.automated_sub_score != null ? rb.automated_sub_score : w.automated_sub_score) + "</div>" +
    '<div class="card"><h3>Technical signals</h3><div class="small">SSL valid: ' + yn(w.ssl_valid) + " &middot; DMARC: " + yn(w.dmarc_exists) +
    " &middot; SPF: " + yn(w.spf_exists) + " &middot; blacklist matches: " + (w.blacklist_matches || 0) + "</div></div>" +
    "<h3>Linked reports</h3>" + ((data.reports || []).map(function (r) {
      return '<div class="card"><a href="/reports/' + encodeURIComponent(r.id) + '">' + window.App.escapeHtml(r.title) + "</a> " +
        window.App.escapeHtml(r.verification_stage || "") + '<div class="small muted">' + window.App.escapeHtml(r.reporter_name || "") +
        " &middot; " + window.App.fmtDateEnIN(r.created_at) + "</div></div>";
    }).join("") || '<div class="card muted">No reports</div>');
});
