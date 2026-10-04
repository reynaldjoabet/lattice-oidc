// Passkeys (WebAuthn) for the end-user pages. Buttons with data-passkey="<purpose>" start a
// ceremony against /passkeys/*; the server keeps the challenge and decides where to go next.
//
//   data-passkey   register | signin | stepup | reauth | approval
//   data-next      where to continue: account, ciba, admin or authz:<ticket>
//   data-approval  the CIBA request id (approval)
//   data-submit    id of a form to submit once verified (stepup, reauth)
//
// Elements marked data-passkey-only stay hidden when the browser has no WebAuthn. An input with
// data-passkey-autofill="<next>" offers saved passkeys in its autofill (conditional mediation).
(function () {
  "use strict";

  if (!window.PublicKeyCredential || !navigator.credentials) {
    return;
  }

  var pending = null; // AbortController of the running ceremony

  // ---------------------------------------------------------------- base64url

  function toBytes(value) {
    var base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) base64 += "=";
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
    return bytes.buffer;
  }

  function toBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var index = 0; index < bytes.length; index++) binary += String.fromCharCode(bytes[index]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // ---------------------------------------------------------------- options and responses

  function creationOptions(options) {
    var publicKey = options.publicKey;
    publicKey.challenge = toBytes(publicKey.challenge);
    publicKey.user.id = toBytes(publicKey.user.id);
    (publicKey.excludeCredentials || []).forEach(function (credential) { credential.id = toBytes(credential.id); });
    return publicKey;
  }

  function requestOptions(options) {
    var publicKey = options.publicKey;
    publicKey.challenge = toBytes(publicKey.challenge);
    (publicKey.allowCredentials || []).forEach(function (credential) { credential.id = toBytes(credential.id); });
    return publicKey;
  }

  function credentialJson(credential) {
    var response = credential.response;
    var json = {
      type: credential.type,
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
      response: { clientDataJSON: toBase64Url(response.clientDataJSON) }
    };
    if (response.attestationObject) {
      json.response.attestationObject = toBase64Url(response.attestationObject);
      if (response.getTransports) json.response.transports = response.getTransports();
    } else {
      json.response.authenticatorData = toBase64Url(response.authenticatorData);
      json.response.signature = toBase64Url(response.signature);
      if (response.userHandle) json.response.userHandle = toBase64Url(response.userHandle);
    }
    return json;
  }

  // ---------------------------------------------------------------- server calls

  function csrfToken() {
    var meta = document.querySelector("meta[name=csrf-token]");
    return meta ? meta.content : "";
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Csrf-Token": csrfToken() },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (json) {
        if (!response.ok) {
          var error = new Error(json.error || "Request failed");
          error.redirect = json.redirect;
          throw error;
        }
        return json;
      });
    });
  }

  function failedUrl(next) {
    return "/passkeys/failed?next=" + encodeURIComponent(next || "account");
  }

  // ---------------------------------------------------------------- waiting panel

  function waiting(show) {
    var panel = document.getElementById("passkey-waiting");
    if (!panel) return;
    panel.hidden = !show;
    if (show) {
      var cancel = panel.querySelector("[data-passkey-cancel]");
      if (cancel) cancel.focus();
    }
  }

  function abortPending() {
    if (pending) {
      pending.abort();
      pending = null;
    }
  }

  // ---------------------------------------------------------------- ceremonies

  function assert(body, mediation, controller) {
    return post("/passkeys/assertion/options", body).then(function (started) {
      var request = { publicKey: requestOptions(started.options), signal: controller.signal };
      if (mediation) request.mediation = mediation;
      return navigator.credentials.get(request).then(function (credential) {
        return post("/passkeys/assertion", { ceremony: started.ceremony, credential: credentialJson(credential) });
      });
    });
  }

  function finish(result, element) {
    if (result.redirect) {
      window.location.assign(result.redirect);
      return;
    }
    var formId = element && element.getAttribute("data-submit");
    var form = formId && document.getElementById(formId);
    if (form) {
      form.submit();
    } else {
      window.location.reload();
    }
  }

  function fail(error, next) {
    waiting(false);
    if (error && error.name === "AbortError") return; // cancelled from the waiting panel
    window.location.assign((error && error.redirect) || failedUrl(next));
  }

  function start(element) {
    var purpose = element.getAttribute("data-passkey");
    var next = element.getAttribute("data-next") || "account";
    abortPending();
    var controller = new AbortController();
    pending = controller;
    waiting(true);
    var ceremony =
      purpose === "register"
        ? registerWith(next, controller)
        : assert({ purpose: purpose, next: next, approval: element.getAttribute("data-approval") }, null, controller);
    ceremony
      .then(function (result) {
        pending = null;
        finish(result, element);
      })
      .catch(function (error) {
        pending = null;
        fail(error, next);
      });
  }

  function registerWith(next, controller) {
    return post("/passkeys/registration/options", { next: next }).then(function (started) {
      return navigator.credentials
        .create({ publicKey: creationOptions(started.options), signal: controller.signal })
        .then(function (credential) {
          return post("/passkeys/registration", { ceremony: started.ceremony, credential: credentialJson(credential) });
        });
    });
  }

  // Passkeys in the username field's autofill. Runs quietly: no waiting panel, and a cancelled
  // or failed autofill leaves the page as it is.
  function autofill(input) {
    if (!PublicKeyCredential.isConditionalMediationAvailable) return;
    PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
      if (!available) return;
      var controller = new AbortController();
      pending = controller;
      var next = input.getAttribute("data-passkey-autofill");
      assert({ purpose: "signin", next: next }, "conditional", controller)
        .then(function (result) {
          finish(result, null);
        })
        .catch(function (error) {
          if (error && error.redirect) window.location.assign(error.redirect);
        });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-passkey-only]").forEach(function (element) { element.hidden = false; });
    document.querySelectorAll("[data-passkey]").forEach(function (element) {
      element.addEventListener("click", function (event) {
        event.preventDefault();
        start(element);
      });
    });
    document.querySelectorAll("[data-passkey-cancel]").forEach(function (element) {
      element.addEventListener("click", function () {
        abortPending();
        waiting(false);
      });
    });
    var input = document.querySelector("[data-passkey-autofill]");
    if (input) autofill(input);
  });
})();
