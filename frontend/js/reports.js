document.addEventListener("DOMContentLoaded", async function () {
  try {
    const params = new URLSearchParams(window.location.search);
    const category = params.get("category") || "";
    const url = "/api/reports?limit=50" + (category ? "&category=" + encodeURIComponent(category) : "");
    const { ok, status, data } = await window.App.api(url);
    if (!ok) throw new Error("API error: " + status);
    const reports = (data && data.reports) || [];
    const cats = ["", "phishing", "investment-scam", "fake-ecommerce", "impersonation", "payment-fraud", "fake-job-scam", "malware", "product-never-delivered", "suspicious-behaviour", "other"];
    document.getElementById("filters").innerHTML = cats.map(function (c) {
      const active = c === category ? ' <strong>(active)</strong>' : "";
      return '<a style="margin-right:.75rem" href="/reports.html' + (c ? "?category=" + c : "") + '">' + (c || "all") + "</a>" + active;
    }).join("");
    const list = document.getElementById("list");
    if (!reports.length) { list.innerHTML = '<div class="card muted">No reports found</div>'; return; }
    list.innerHTML = reports.map(function (r) {
      const lvl = (r.website_risk_level || "other").toLowerCase();
      const badge = '<span class="pill ' + (["critical", "high", "medium"].indexOf(lvl) >= 0 ? lvl : "other") + '">' + window.App.escapeHtml((r.website_risk_level || "other").toUpperCase()) + "</span>";
      return '<div class="card"><a href="/reports/' + encodeURIComponent(r.report_id) + '"><strong>' + window.App.escapeHtml(r.title) +
        "</strong></a> " + badge + '<div class="small muted">' + window.App.escapeHtml(r.domain || "") + " &middot; confirm " +
        (r.confirm_votes || 0) + " / deny " + (r.deny_votes || 0) + " &middot; evidence " + (r.evidence_count || 0) + "</div></div>";
    }).join("");
  } catch (e) {
    console.error("Reports page error:", e);
    const list = document.getElementById("list");
    if (list) list.innerHTML = '<div class="card error">Failed to load reports: ' + window.App.escapeHtml(String(e)) + '</div>';
  }
});
