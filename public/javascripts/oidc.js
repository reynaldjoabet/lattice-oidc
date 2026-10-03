// Prevents double submission of forms (e.g. double-clicking "Authorize"), which would send the
// same single-use ticket twice. Buttons are disabled after the browser has captured the form
// data, so the clicked button's name/value is still submitted. No inline script (CSP).
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
