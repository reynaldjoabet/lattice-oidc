// Progressive enhancements for the end-user pages. Pages work without JavaScript; no inline
// scripts are used (CSP).

// 1. Prevent double submission (e.g. double-clicking "Allow"), which would send the same
//    single-use ticket twice. Buttons are disabled after the browser has captured the form data,
//    so the clicked button's name/value is still submitted.
document.addEventListener("submit", function (event) {
  var form = event.target;
  if (form.dataset.submitted === "true") {
    event.preventDefault();
    return;
  }
  form.dataset.submitted = "true";
  setTimeout(function () {
    form.querySelectorAll("button[type=submit]").forEach(function (b) { b.disabled = true; });
  }, 0);
});

// 2. Show/hide toggle for password fields wrapped in .password.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll(".password").forEach(function (wrap) {
    var input = wrap.querySelector("input");
    if (!input) return;
    var toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "toggle";
    toggle.textContent = "Show";
    toggle.setAttribute("aria-label", "Show password");
    toggle.setAttribute("aria-pressed", "false");
    toggle.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      toggle.textContent = show ? "Hide" : "Show";
      toggle.setAttribute("aria-label", show ? "Hide password" : "Show password");
      toggle.setAttribute("aria-pressed", String(show));
      input.focus();
    });
    wrap.appendChild(toggle);
  });
});
