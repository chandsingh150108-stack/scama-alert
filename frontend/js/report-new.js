document.addEventListener("DOMContentLoaded", async function () {
  const me = await window.App.api("/api/me");
  const logged = me.ok && me.data && me.data.user;
  if (!logged) {
    document.getElementById("anon-banner").innerHTML =
      '<div class="alert">Reporting requires sign-in. <button class="btn" data-auth-open="signin">Sign In</button> ' +
      '<button class="btn gray" data-auth-open="signup">Create Account</button></div>';
    document.querySelectorAll("[data-auth-open]").forEach(function (el) {
      el.onclick = function () { window.Auth.openAuthModal(el.getAttribute("data-auth-open")); };
    });
  } else {
    document.getElementById("anon-row").style.display = "block";
  }
  const allowed = ["image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain",
    "text/html", "video/mp4", "video/webm", "audio/mpeg", "audio/wav"];
  let files = [];
  const input = document.getElementById("files");
  const list = document.getElementById("file-list");
  function renderFiles() {
    list.innerHTML = files.map(function (f, i) {
      return "<div>" + window.App.escapeHtml(f.name) + ' <button data-rm="' + i + '">Remove</button></div>';
    }).join("");
    list.querySelectorAll("button[data-rm]").forEach(function (b) {
      b.onclick = function () { files.splice(Number(b.getAttribute("data-rm")), 1); renderFiles(); };
    });
  }
  input.addEventListener("change", function () {
    Array.from(input.files || []).forEach(function (f) {
      if (f.size > 10 * 1024 * 1024) return; // silent drop (parity with TS)
      if (allowed.indexOf(f.type) < 0) return;
      files.push(f);
    });
    renderFiles();
    input.value = "";
  });
  document.getElementById("report-form").addEventListener("submit", async function (e) {
    e.preventDefault();
    const err = document.getElementById("form-error");
    err.style.display = "none";
    // Report submission requires a signed-in session (POST /api/reports
    // returns 401 for guests).
    if (!logged) {
      err.innerHTML = "Please sign in to submit a report. " +
        '<button class="btn" id="rep-signin" type="button">Sign In</button>';
      err.style.display = "block";
      document.getElementById("rep-signin").onclick = function () { window.Auth.openAuthModal("signin"); };
      return;
    }
    const btn = document.getElementById("submit-btn");
    btn.disabled = true; btn.textContent = "Submitting…";
    const fd = new FormData(e.target);
    let amount = fd.get("amount_lost");
    amount = amount === "" || amount == null ? null : parseFloat(amount);
    const payload = {
      url: fd.get("url"), category_slug: fd.get("category_slug"), title: fd.get("title"),
      description: fd.get("description"), target_brand: fd.get("target_brand") || null,
      amount_lost: amount, currency: "INR", incident_date: fd.get("incident_date") || null,
      country_code: "IN", is_anonymous: !!fd.get("is_anonymous"),
    };
    const res = await window.App.api("/api/reports", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!res.ok) { err.textContent = (res.data && res.data.error) || "Submission failed"; err.style.display = "block"; btn.disabled = false; btn.textContent = "Submit Report"; return; }
    const rid = res.data.report_id;
    const failures = [];
    for (let i = 0; i < files.length; i++) {
      btn.textContent = "Uploading file " + (i + 1) + " of " + files.length + "…";
      const form = new FormData();
      form.append("file", files[i]);
      form.append("report_id", rid);
      try {
        const up = await fetch("/api/evidence/upload", { method: "POST", body: form, credentials: "same-origin" });
        if (!up.ok) {
          let reason = "Upload failed";
          try { reason = (await up.json()).error || reason; } catch (e) {}
          failures.push(files[i].name + ": " + reason);
        }
      } catch (e) {
        failures.push(files[i].name + ": Network error");
      }
    }
    if (failures.length === 0) {
      window.location.href = "/reports/" + encodeURIComponent(rid);
      return;
    }
    btn.disabled = false; btn.textContent = "Submit Report";
    err.style.display = "block";
    err.innerHTML = "Report submitted, but " + failures.length + " file(s) failed to upload:<br>" +
      failures.map(function (f) { return window.App.escapeHtml(f); }).join("<br>") +
      '<br><a href="/reports/' + encodeURIComponent(rid) + '">View your report</a>';
  });
});
