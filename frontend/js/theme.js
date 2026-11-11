/* Theme toggle + persistence + nav active state. No API or business logic. */
(function () {
  var KEY = "scamalert-theme";

  function current() {
    return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
  }

  function paintButton() {
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    var dark = current() === "dark";
    b.textContent = dark ? "\u2600" : "\u263E";
    b.setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
    b.setAttribute("title", dark ? "Light theme" : "Dark theme");
  }

  function apply(t) {
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem(KEY, t); } catch (e) {}
    paintButton();
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Active-page indication in header nav.
    var path = window.location.pathname.replace(/\/$/, "") || "/";
    document.querySelectorAll("nav.main a").forEach(function (a) {
      var href = a.getAttribute("href") || "";
      if (href.charAt(0) !== "/") return;
      var norm = href.replace(/\.html$/, "") || "/";
      if (path === href || path === norm || (norm !== "/" && path.indexOf(norm + "/") === 0)) {
        a.setAttribute("aria-current", "page");
      }
    });
    // Compact toggle appended to the shared user area (present on all pages).
    var box = document.querySelector(".userbox");
    if (box && !document.getElementById("theme-toggle")) {
      var btn = document.createElement("button");
      btn.id = "theme-toggle";
      btn.className = "theme-toggle";
      btn.type = "button";
      btn.onclick = function () { apply(current() === "dark" ? "light" : "dark"); };
      box.appendChild(btn);
    }
    // Sync with FOUC pre-init (same value; also paints the button).
    apply(current());
  });

  window.Theme = { apply: apply, current: current };
})();
