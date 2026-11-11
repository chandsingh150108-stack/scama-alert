function reportId() {
  const m = window.location.pathname.match(/\/reports\/([^\/\.]+)/);
  if (m) return decodeURIComponent(m[1]);
  return new URLSearchParams(window.location.search).get("id");
}
document.addEventListener("DOMContentLoaded", async function () {
  try {
    const id = reportId();
    const box = document.getElementById("detail");
    if (!id) { box.innerHTML = '<div class="card">Report not found.</div>'; return; }
    const { ok, status, data } = await window.App.api("/api/reports/" + encodeURIComponent(id));
    if (!ok) throw new Error("API error: " + status);
    if (!data || !data.report) { box.innerHTML = '<div class="card">Report not found.</div>'; return; }

    const r = data.report;
    const anon = r.is_anonymous === 1 || r.is_anonymous === true;
    const tags = (data.tags || []).map(function (t) { return '<span class="tag">' + window.App.escapeHtml(t.name || t.slug || "") + "</span>"; }).join("");
    const ev = (data.evidence || []).map(function (e) {
      const label = window.App.escapeHtml(e.file_name || e.file_path || "");
      const type = window.App.escapeHtml(e.evidence_type || "");
      const href = e.file_path ? encodeURI(e.file_path) : null;
      const link = href ? '<a href="' + href + '" target="_blank" rel="noopener">' + label + "</a>" : label;
      const isImg = (e.mime_type || "").indexOf("image/") === 0 || e.evidence_type === "screenshot";
      const thumb = (href && isImg)
        ? '<br><a href="' + href + '" target="_blank" rel="noopener"><img src="' + href + '" alt="' + label + '" loading="lazy" style="max-width:240px;border:1px solid #ccc"></a>'
        : "";
      return '<div class="small">' + link + " (" + type + ")" + thumb + "</div>";
    }).join("") || '<div class="muted small">No evidence uploaded</div>';
    const votes = data.votes || [];
    const comments = data.comments || [];
    const me = await window.App.api("/api/me");
    const isOwner = me.ok && me.data && me.data.user && me.data.user.id === r.reporter_id;
    const isAdmin = me.ok && me.data && me.data.user && (me.data.user.role === 'admin' || me.data.user.role === 'moderator');
    const canDelete = isOwner || isAdmin;

    box.innerHTML =
      "<h1>" + window.App.escapeHtml(r.title) + "</h1>" +
      '<div class="small muted">status ' + window.App.escapeHtml(r.status || "") + " &middot; stage " +
      window.App.escapeHtml(r.verification_stage || "") + "</div>" +
      "<p>" + window.App.escapeHtml(r.description) + "</p>" +
      (tags ? "<div>" + tags + "</div>" : "") +
      (r.amount_lost ? "<p><strong>\u20b9" + Number(r.amount_lost).toLocaleString("en-IN") + " lost</strong></p>" : "") +
      '<p><a href="/websites/' + encodeURIComponent(r.website_url_id || "") + '">Website risk dashboard</a> &middot; ' +
      '<a href="/api/reports/' + encodeURIComponent(id) + '/complaint">Download Complaint (DOCX)</a>' +
      (canDelete ? ' &middot; <button class="btn gray" id="delete-report" style="background:none;border:none;color:var(--danger);cursor:pointer;padding:0">Delete report</button>' : '') + '</p>' +
      (anon ? '<div class="card small">Reported anonymously</div>' :
        '<div class="card small">Reporter: <a href="/users/' + encodeURIComponent(r.reporter_id || "") + '">' +
        window.App.escapeHtml(r.reporter_name || "") + "</a> " + window.App.tierPill(r.reporter_tier) + "</div>") +
      '<div class="card"><h3>Verify</h3><div id="vote-box"></div><div class="small muted">' + votes.length + " votes recorded</div></div>" +
      '<div class="card"><h3>Evidence</h3>' + ev + "</div>" +
      '<div class="card"><h3>Comments (' + comments.length + ")</h3><div id='comments'>" +
      comments.map(function (c) {
        const up = c.upvotes || 0;
        const down = c.downvotes || 0;
        const userVote = c.user_vote || 0;
        const score = up - down;
        const canVote = window.Auth && window.Auth.currentUser &&
          ((window.Auth.currentUser.reputation_score >= 40) ||
           window.Auth.currentUser.role === 'moderator' ||
           window.Auth.currentUser.role === 'admin');
        const voteBtns = canVote
          ? ('<div class="comment-votes">' +
            '<button class="vote-btn ' + (userVote === 1 ? 'voted' : '') + '" data-cid="' + c.id + '" data-vote="1" title="Upvote">▲</button>' +
            '<span class="vote-score">' + score + '</span>' +
            '<button class="vote-btn ' + (userVote === -1 ? 'voted' : '') + '" data-cid="' + c.id + '" data-vote="-1" title="Downvote">▼</button>' +
            '</div>')
          : '<div class="comment-votes"><span class="vote-score">' + score + '</span></div>';
        return '<div class="comment" data-cid="' + c.id + '"><div class="comment-header">' +
          '<strong>' + window.App.escapeHtml(c.user_name || "") + "</strong> " +
          window.App.tierPill(c.user_tier) + voteBtns + '</div>' +
          '<div class="comment-body">' + window.App.escapeHtml(c.body || "") + '</div></div>';
      }).join("") + '</div><textarea id="comment-body" rows="3" placeholder="Add a comment…"></textarea>' +
      '<p><button class="btn" id="comment-submit">Comment</button></p><div id="comment-error" class="error" style="display:none"></div></div>';

    // votes
    let selected = null;
    const vb = document.getElementById("vote-box");
    const counts = { confirm: r.confirm_votes || 0, deny: r.deny_votes || 0 };
    function renderVotes() {
      vb.innerHTML = ["confirm", "deny", "inconclusive"].map(function (t) {
        const dis = selected ? "disabled" : "";
        return '<button class="btn gray" data-vote="' + t + '" ' + dis + ">" + t + "</button> ";
      }).join("") + '<div class="small muted">' + (r.total_votes || 0) + " total votes</div>";
      vb.querySelectorAll("button[data-vote]").forEach(function (b) {
        b.onclick = async function () {
          if (selected) return;
          const me = await window.App.api("/api/me");
          if (!me.ok) { window.Auth.openAuthModal("signin"); return; }
          const res = await window.App.api("/api/reports/" + encodeURIComponent(id) + "/vote", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vote_type: b.getAttribute("data-vote"), confidence: 1.0 }),
          });
          if (res.ok) { selected = b.getAttribute("data-vote"); renderVotes(); }
          else alert((res.data && res.data.error) || "Vote failed");
        };
      });
    }
    renderVotes();

    // comment vote handlers (event delegation on #comments)
    document.getElementById("comments").addEventListener("click", async function (e) {
      const btn = e.target.closest(".vote-btn");
      if (!btn) return;
      const cid = btn.getAttribute("data-cid");
      const vote = parseInt(btn.getAttribute("data-vote"), 10);
      if (isNaN(vote)) return;

      const me = await window.App.api("/api/me");
      if (!me.ok) { window.Auth.openAuthModal("signin"); return; }

      btn.disabled = true;
      const res = await window.App.api("/api/reports/" + encodeURIComponent(id) + "/comments/" + encodeURIComponent(cid) + "/vote", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ vote_value: vote }),
      });
      btn.disabled = false;

      if (res.ok && res.data) {
        const commentEl = document.querySelector('.comment[data-cid="' + cid + '"]');
        if (commentEl) {
          const scoreEl = commentEl.querySelector(".vote-score");
          const upBtn = commentEl.querySelector('.vote-btn[data-vote="1"]');
          const downBtn = commentEl.querySelector('.vote-btn[data-vote="-1"]');
          if (scoreEl) scoreEl.textContent = res.data.upvotes - res.data.downvotes;
          if (upBtn) upBtn.classList.toggle("voted", res.data.user_vote === 1);
          if (downBtn) downBtn.classList.toggle("voted", res.data.user_vote === -1);
        }
      } else {
        alert((res.data && res.data.error) || "Vote failed");
      }
    });

    // comment (guests allowed; stored under the Anonymous user)
    document.getElementById("comment-submit").onclick = async function () {
      const body = document.getElementById("comment-body").value;
      const err = document.getElementById("comment-error");
      err.style.display = "none";
      if (!body.trim()) return;
      const res = await window.App.api("/api/reports/" + encodeURIComponent(id) + "/comment", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body: body.trim() }),
      });
      if (!res.ok) { err.textContent = (res.data && res.data.error) || "Failed"; err.style.display = "block"; return; }
      document.getElementById("comment-body").value = "";
      window.location.reload();
    };

    // delete report (owner or admin)
    const delBtn = document.getElementById("delete-report");
    if (delBtn) {
      delBtn.onclick = async function () {
        if (!confirm("Delete this report? This cannot be undone.")) return;
        const res = await window.App.api("/api/reports/" + encodeURIComponent(id), { method: "DELETE" });
        if (!res.ok) { alert((res.data && res.data.error) || "Delete failed"); return; }
        window.location.href = "/reports.html";
      };
    }
  } catch (e) {
    console.error("Report detail error:", e);
    const box = document.getElementById("detail");
    if (box) box.innerHTML = '<div class="card error">Failed to load report: ' + window.App.escapeHtml(String(e)) + '</div>';
  }
});
