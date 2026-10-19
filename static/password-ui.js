// NIST SP 800-63B Rev. 4 §3.1.1.2 front-end guidance:
//  * "SHOULD offer an option to display the password while it is entered"
//  * "SHALL offer guidance ... such as a password-strength meter"
//  * paste and autofill are never blocked (no onpaste handlers anywhere).
(function () {
  document.querySelectorAll("input.password-input").forEach(function (input) {
    var tools = document.createElement("div");
    tools.className = "pw-tools";
    var toggle = document.createElement("label");
    toggle.style.cssText = "display:inline-flex;gap:6px;align-items:center;font-weight:400;margin:0";
    var cb = document.createElement("input");
    cb.type = "checkbox";
    cb.addEventListener("change", function () { input.type = cb.checked ? "text" : "password"; });
    toggle.appendChild(cb);
    toggle.appendChild(document.createTextNode("Show password"));
    tools.appendChild(toggle);

    if (input.getAttribute("autocomplete") === "new-password" && !input.name.endsWith("2")) {
      var count = document.createElement("span");
      var meter = document.createElement("div");
      meter.className = "meter";
      var bar = document.createElement("div");
      meter.appendChild(bar);
      var update = function () {
        var n = Array.from(input.value).length; // code points, like NIST and Django
        count.textContent = n + " character" + (n === 1 ? "" : "s") + (n < 15 ? " (need 15)" : "");
        var pct = Math.min(100, Math.round((n / 24) * 100));
        bar.style.width = pct + "%";
        bar.style.background = n < 15 ? "#b3261e" : n < 20 ? "#c98a00" : "#1d7a4d";
      };
      input.addEventListener("input", update);
      update();
      tools.appendChild(count);
      input.insertAdjacentElement("afterend", meter);
      meter.insertAdjacentElement("afterend", tools);
    } else {
      input.insertAdjacentElement("afterend", tools);
    }
  });
})();
