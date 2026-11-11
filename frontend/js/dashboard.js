document.addEventListener("DOMContentLoaded", async function () {
  try {
    const feed = document.getElementById("feed");
    const [rep, users] = await Promise.all([
      window.App.api("/api/reports?limit=20"),
      window.App.api("/api/users?limit=5"),
    ]);
    if (!rep.ok) throw new Error("Reports API error: " + rep.status);
    if (!users.ok) throw new Error("Users API error: " + users.status);
    const reports = (rep.data && rep.data.reports) || [];
    const total = (rep.data && rep.data.pagination && rep.data.pagination.total) || 0;
    feed.innerHTML = reports.length === 0
      ? '<div class="card muted" style="text-align:center;padding:3rem">No reports yet. Be the first to submit one.</div>'
      : reports.map(window.App.reportCard).join("");

    // Dynamic categories with real counts and correct database slugs
    const catCounts = {};
    reports.forEach(function (r) {
      const slug = r.category_slug;
      if (slug) {
        if (!catCounts[slug]) {
          catCounts[slug] = { name: r.category_name || slug, slug: slug, count: 0 };
        }
        catCounts[slug].count += 1;
      }
    });
    const catList = Object.values(catCounts).sort(function (a, b) { return b.count - a.count; });
    document.getElementById("cats").innerHTML = catList.length === 0
      ? '<div class="muted">No categories active</div>'
      : catList.map(function (c) {
          return '<div style="margin-bottom:0.4rem;display:flex;justify-content:space-between;align-items:center">' +
            '<a href="/reports.html?category=' + encodeURIComponent(c.slug) + '">' + window.App.escapeHtml(c.name) + '</a>' +
            '<span class="tag" style="margin:0">' + c.count + '</span>' +
          '</div>';
        }).join("");

    const ulist = (users.data && users.data.users) || [];
    document.getElementById("top").innerHTML = ulist.slice(0, 5).map(function (u) {
      return '<div style="margin-bottom:0.4rem;display:flex;justify-content:space-between;align-items:center">' +
        '<div>' + window.App.escapeHtml(u.name) + ' ' + window.App.tierPill(u.reputation_tier) + '</div>' +
        '<strong style="color:var(--primary)">' + (u.reputation_score || 0) + '</strong>' +
      '</div>';
    }).join("");

    const highRisk = reports.filter(function (r) {
      const lvl = (r.website_risk_level || "").toLowerCase();
      return lvl === "critical" || lvl === "high";
    }).length;
    const verified = reports.filter(function (r) {
      const s = (r.verification_stage || "").toLowerCase();
      return s === "community_verified" || s === "confirmed_malicious";
    }).length;
    const totalLost = reports.reduce(function (sum, r) { return sum + (Number(r.amount_lost) || 0); }, 0);

    document.getElementById("stats").innerHTML =
      '<div style="margin-bottom:0.45rem;display:flex;justify-content:space-between"><span>Total Reports</span><strong>' + total + '</strong></div>' +
      '<div style="margin-bottom:0.45rem;display:flex;justify-content:space-between"><span>High / Critical Risk</span><strong style="color:#dc2626">' + highRisk + '</strong></div>' +
      '<div style="margin-bottom:0.45rem;display:flex;justify-content:space-between"><span>Verified Scams</span><strong style="color:#16a34a">' + verified + '</strong></div>' +
      '<div style="margin-bottom:0.45rem;display:flex;justify-content:space-between"><span>Total Fraud Loss</span><strong style="color:#ea580c">₹' + totalLost.toLocaleString("en-IN") + '</strong></div>';
  } catch (e) {
    console.error("Dashboard error:", e);
    const feed = document.getElementById("feed");
    if (feed) feed.innerHTML = '<div class="card error">Failed to load dashboard: ' + window.App.escapeHtml(String(e)) + '</div>';
  }
});
