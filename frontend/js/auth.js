/* Auth widget + modal. Replaces UserMenu + AuthModal + AnonymousBanner + auth-client. */
async function refreshUserMenu() {
  const slot = document.getElementById("user-menu");
  if (!slot) return;
  const { ok, data } = await window.App.api("/api/me");
  if (!ok || !data || !data.user) {
    slot.innerHTML = '<button class="btn" id="signin-btn">Sign In</button><div class="modal-backdrop" id="auth-backdrop"><div class="modal" id="auth-modal"></div></div>';
    document.getElementById("signin-btn").onclick = function () { openAuthModal("signin"); };
    document.getElementById("auth-backdrop").onclick = function (e) { if (e.target.id === "auth-backdrop") closeAuthModal(); };
    return;
  }
  const u = data.user;
  const initial = escapeHtml((u.name || u.email || "U").trim().charAt(0).toUpperCase());
  slot.innerHTML = '<button class="btn" id="avatar-btn" title="' + escapeHtml(u.email || "") + '">' + initial +
    '</button><div class="modal-backdrop" id="auth-backdrop"><div class="modal" id="auth-modal"></div></div>' +
    '<div id="user-dropdown" style="display:none;position:absolute;background:var(--surface);border:1px solid var(--border);border-radius:.375rem;padding:.5rem;"></div>';
  const dd = document.getElementById("user-dropdown");
  const isAdminOrMod = u.role === "admin" || u.role === "moderator";
  dd.innerHTML = '<div class="small"><strong>' + escapeHtml(u.name || u.email) + '</strong> ' + window.App.tierPill(u.reputation_tier) + '</div>' +
    '<div class="small muted" style="margin-bottom:0.4rem">' + escapeHtml(u.role) + ' &bull; Rep: ' + (u.reputation_score || 0) + '</div>' +
    '<div><a href="/users/' + encodeURIComponent(u.id) + '">My Profile</a></div>' +
    (isAdminOrMod ? '<div><a href="/admin">👑 Admin Panel</a></div>' : '') +
    '<div style="margin-top:0.4rem"><button class="btn gray small" id="signout-btn">Sign Out</button></div>';
  document.getElementById("avatar-btn").onclick = function () {
    dd.style.display = dd.style.display === "none" ? "block" : "none";
  };
  document.getElementById("signout-btn").onclick = async function () {
    await window.App.api("/api/auth/logout", { method: "POST" });
    window.location.reload();
  };
  document.getElementById("auth-backdrop").onclick = function (e) { if (e.target.id === "auth-backdrop") closeAuthModal(); };
}
function openAuthModal(tab) {
  let backdrop = document.getElementById("auth-backdrop");
  if (!backdrop) {
    const slot = document.getElementById("user-menu") || document.body;
    const div = document.createElement("div");
    div.innerHTML = '<div class="modal-backdrop open" id="auth-backdrop"><div class="modal" id="auth-modal"></div></div>';
    slot.appendChild(div.firstChild);
    backdrop = document.getElementById("auth-backdrop");
    backdrop.onclick = function (e) { if (e.target.id === "auth-backdrop") closeAuthModal(); };
  }
  backdrop.classList.add("open");
  renderAuthForm(tab === "signup" ? "signup" : "signin");
}
function closeAuthModal() {
  const b = document.getElementById("auth-backdrop");
  if (b) b.classList.remove("open");
}
function renderAuthForm(tab) {
  const m = document.getElementById("auth-modal");
  if (!m) return;
  const nameField = tab === "signup" ? '<label>Name<input id="auth-name" type="text" required></label>' : "";
  const demoPills = tab === "signin"
    ? '<div class="small muted" style="margin-top:0.75rem;border-top:1px dashed var(--border);padding-top:0.5rem">' +
      '<div style="margin-bottom:0.3rem">Quick fill demo (pwd: <code>Password@123</code>):</div>' +
      '<button type="button" class="btn gray small" style="padding:0.2rem 0.4rem;font-size:0.75rem;margin-right:0.3rem" onclick="document.getElementById(\'auth-email\').value=\'admin@scamalert.in\';document.getElementById(\'auth-password\').value=\'Password@123\'">👑 Admin</button>' +
      '<button type="button" class="btn gray small" style="padding:0.2rem 0.4rem;font-size:0.75rem;margin-right:0.3rem" onclick="document.getElementById(\'auth-email\').value=\'moderator@scamalert.in\';document.getElementById(\'auth-password\').value=\'Password@123\'">🛡️ Mod</button>' +
      '</div>'
    : "";
  m.innerHTML = "<h3>" + (tab === "signup" ? "Create account" : "Sign in") + "</h3>" +
    '<div class="tabs"><button class="btn gray" id="tab-signin">Sign in</button>' +
    '<button class="btn gray" id="tab-signup">Sign up</button></div>' +
    '<div id="auth-error" class="error" style="display:none"></div>' +
    nameField + '<label>Email<input id="auth-email" type="email" autocomplete="email" required></label>' +
    '<label>Password<input id="auth-password" type="password" autocomplete="current-password" required></label>' +
    '<p><button class="btn" id="auth-submit">' + (tab === "signup" ? "Create account" : "Sign in") + "</button> " +
    '<button class="btn gray" id="auth-close">Close</button></p>' + demoPills;
  document.getElementById("tab-signin").onclick = function () { renderAuthForm("signin"); };
  document.getElementById("tab-signup").onclick = function () { renderAuthForm("signup"); };
  document.getElementById("auth-close").onclick = closeAuthModal;
  document.getElementById("auth-submit").onclick = async function () {
    const err = document.getElementById("auth-error");
    err.style.display = "none";
    const email = (document.getElementById("auth-email").value || "").trim().toLowerCase();
    const password = document.getElementById("auth-password").value;
    if (tab === "signup") {
      const name = document.getElementById("auth-name").value;
      if (!name || !email || !password) { err.textContent = "All fields are required"; err.style.display = "block"; return; }
      if (password.length < 8) { err.textContent = "Password must be at least 8 characters"; err.style.display = "block"; return; }
      const r = await window.App.api("/api/auth/signup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, email, password }) });
      if (!r.ok) { err.textContent = (r.data && r.data.error) || "Signup failed"; err.style.display = "block"; return; }
    } else {
      if (!email || !password) { err.textContent = "Email and password are required"; err.style.display = "block"; return; }
      const r = await window.App.api("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
      if (!r.ok) { err.textContent = (r.data && r.data.error) || "Login failed"; err.style.display = "block"; return; }
    }
    closeAuthModal();
    window.location.reload();
  };
}
function wireAnonymousBanner() {
  document.querySelectorAll("[data-auth-open]").forEach(function (el) {
    el.addEventListener("click", function () { openAuthModal(el.getAttribute("data-auth-open") || "signin"); });
  });
}
document.addEventListener("DOMContentLoaded", function () {
  refreshUserMenu();
  wireAnonymousBanner();
});
function escapeHtml(s) { return window.App.escapeHtml(s); }
window.Auth = { refreshUserMenu, openAuthModal, closeAuthModal };
