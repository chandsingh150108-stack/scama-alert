document.addEventListener("DOMContentLoaded", async function () {
  const box = document.getElementById("box");
  const me = await window.App.api("/api/me");
  if (!me.ok) { box.innerHTML = '<div class="card">Loading…</div>'; return; }
  let configs = [];
  async function load() {
    const r = await window.App.api("/api/admin/config");
    if (!r.ok) { box.innerHTML = '<div class="error">' + window.App.escapeHtml((r.data && r.data.error) || "Forbidden") + "</div>"; return; }
    configs = r.data.configs || [];
    if (!configs.length) { box.innerHTML = '<div class="card muted">No config entries</div>'; return; }
    box.innerHTML = configs.map(function (c, i) {
      const val = typeof c.value === "string" ? c.value : JSON.stringify(c.value);
      return '<div class="card"><strong>' + window.App.escapeHtml(c.key || c["key"]) + "</strong><div class='small'>" +
        window.App.escapeHtml(val) + "</div><div data-edit='" + i + "' style='display:none'><input data-v='" + i +
        "' value='" + window.App.escapeHtml(val).replace(/'/g, "&#39;") + "'><input data-d='" + i + "' value='" +
        window.App.escapeHtml(c.description || "") + "'><button data-save='" + i + "'>Save</button> <button data-cancel='" + i + "'>Cancel</button></div>" +
        "<button data-editbtn='" + i + "'>Edit</button></div>";
    }).join("");
    box.querySelectorAll("[data-editbtn]").forEach(function (b) {
      b.onclick = function () {
        const i = b.getAttribute("data-editbtn");
        box.querySelector("[data-edit='" + i + "']").style.display = "block";
      };
    });
    box.querySelectorAll("[data-save]").forEach(function (b) {
      b.onclick = async function () {
        const i = b.getAttribute("data-save");
        const v = box.querySelector("[data-v='" + i + "']").value;
        const d = box.querySelector("[data-d='" + i + "']").value;
        let parsed = v;
        try { parsed = JSON.parse(v); } catch (e) { parsed = v; }
        b.textContent = "Saving…";
        const res = await window.App.api("/api/admin/config", { method: "PUT", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key: configs[Number(i)].key || configs[Number(i)]["key"], value: parsed, description: d }) });
        if (res.ok) load(); else { alert((res.data && res.data.error) || "Failed"); b.textContent = "Save"; }
      };
    });
    box.querySelectorAll("[data-cancel]").forEach(function (b) {
      b.onclick = function () { box.querySelector("[data-edit='" + b.getAttribute("data-cancel") + "']").style.display = "none"; };
    });
  }
  document.getElementById("toggle-new").onclick = function () {
    const p = document.getElementById("new-panel");
    p.style.display = p.style.display === "none" ? "block" : "none";
  };
  document.getElementById("cancel").onclick = function () { document.getElementById("new-panel").style.display = "none"; };
  document.getElementById("create").onclick = async function () {
    const k = document.getElementById("nk").value, v = document.getElementById("nv").value, d = document.getElementById("nd").value;
    if (!k || !v) return;
    let parsed = v;
    try { parsed = JSON.parse(v); } catch (e) { parsed = v; }
    this.textContent = "Saving…";
    const res = await window.App.api("/api/admin/config", { method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: k, value: parsed, description: d || undefined }) });
    this.textContent = "Save";
    if (res.ok) { document.getElementById("new-panel").style.display = "none"; load(); }
    else alert((res.data && res.data.error) || "Failed");
  };
  document.getElementById("recalc").onclick = async function () {
    const res = await window.App.api("/api/admin/recalculate-risk", { method: "POST" });
    alert(res.ok ? "Recalculation started" : ((res.data && res.data.error) || "Failed"));
  };
  load();
});
