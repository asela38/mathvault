(function () {
  var $ = function (id) { return document.getElementById(id); };
  var csrf = (document.cookie.match(/csrftoken=([^;]+)/) || [])[1];
  var state = { m: 0, k: 0, built: false };

  function params() {
    return { passwords: $("passwords").value.split("\n"), fp_rate: parseFloat($("fp").value) };
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrf },
      body: JSON.stringify(body)
    }).then(function (r) { return r.ok ? r.json() : r.text().then(function (t) { throw new Error(t); }); });
  }
  function sleep(ms) { return new Promise(function (res) { setTimeout(res, ms); }); }
  function fmt(x) { return Number(x).toLocaleString(); }

  function drawGrid(m) {
    var grid = $("grid"); grid.innerHTML = "";
    var frag = document.createDocumentFragment();
    for (var i = 0; i < m; i++) { var d = document.createElement("div"); d.className = "bit"; d.id = "b" + i; d.title = "bit " + i; frag.appendChild(d); }
    grid.appendChild(frag);
    $("m-label").textContent = fmt(m);
    $("bitgrid-wrap").hidden = false;
  }
  function clearProbeMarks() { document.querySelectorAll(".bit.hit,.bit.miss,.bit.flash").forEach(function (b) { b.classList.remove("hit", "miss", "flash"); }); }

  async function build() {
    $("build-error").textContent = "";
    var data;
    try { data = await post("/accounts/simulation/api/build/", params()); }
    catch (e) { $("build-error").textContent = e.message; return; }
    var s = data.sizing; state.m = s.m; state.k = s.k; state.built = true;
    $("sizing-text").innerHTML =
      "n = " + fmt(s.n) + " passwords, p = " + s.p + "<br>" +
      "m = −n·ln p / (ln 2)² = " + s.m_raw.toFixed(1) + " → rounded up to a multiple of 64 = <b>" + fmt(s.m) + " bits</b> (" + fmt(s.bytes) + " bytes with header)<br>" +
      "k = (m/n)·ln 2 = " + s.k_raw.toFixed(2) + " → <b>" + s.k + " hash positions</b> per password";
    $("sizing").hidden = false;
    drawGrid(s.m);
    $("header").textContent = data.header.replace(/(..)/g, "$1 ").trim();
    var table = $("trace");
    table.innerHTML = "<tr><th>password</th><th>SHA-1 (h1 | h2 | rest)</th><th>positions</th></tr>";
    $("trace-wrap").hidden = false;
    var animate = $("animate").checked;
    var set = {};
    for (var idx = 0; idx < data.items.length; idx++) {
      var it = data.items[idx];
      var tr = document.createElement("tr"); tr.className = "current";
      tr.innerHTML = "<td>" + esc(it.password) + "</td><td class='mono'><b>" + it.h1_hex + "</b> <u>" + it.h2_hex + "</u> " + it.sha1.slice(32) + "</td><td class='mono'>" + it.positions.join(", ") + "</td>";
      table.appendChild(tr);
      for (var j = 0; j < it.positions.length; j++) {
        var cell = $("b" + it.positions[j]);
        if (animate) { cell.classList.add("flash"); await sleep(40); cell.classList.remove("flash"); }
        cell.classList.add("set"); set[it.positions[j]] = 1;
      }
      tr.className = "";
      if (animate) await sleep(120);
    }
    // reconcile with the server's bit array (must be identical)
    data.set_bits.forEach(function (b) { $("b" + b).classList.add("set"); });
    $("fill").innerHTML = fmt(data.set_bits.length) + " of " + fmt(s.m) + " bits set (" + (100 * data.fill_ratio).toFixed(1) + "%). False-positive rate for a never-seen password: " +
      "<b>measured " + (100 * data.measured_fp).toFixed(2) + "%</b> over " + fmt(data.measured_samples) + " random strings; formula (1 − e<sup>−kn/m</sup>)<sup>k</sup> says " + (100 * data.estimated_fp).toFixed(3) + "%, target " + (100 * s.p) + "%. " +
      "At toy sizes the measured rate is higher because the k positions of two passwords are correlated (both are arithmetic progressions mod a tiny m); at 36 billion bits the formula holds.";
  }

  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  async function showCheck(data, extraNote) {
    clearProbeMarks();
    var t = data.trace, steps = $("check-steps");
    steps.innerHTML = "";
    var li = function (html) { var e = document.createElement("li"); e.innerHTML = html; steps.appendChild(e); return e; };
    li("SHA-1(" + esc(JSON.stringify(t.password)) + ") = <span class='mono'><b>" + t.h1_hex + "</b> <u>" + t.h2_hex + "</u> " + t.sha1.slice(32) + "</span>");
    li("h1 = " + t.h1 + ", h2 = " + t.h2 + " (made odd), k = " + data.sizing.k + ", m = " + fmt(data.sizing.m));
    $("check-result").hidden = false;
    var animate = $("animate").checked;
    var stopped = false;
    for (var i = 0; i < data.bits.length; i++) {
      var b = data.bits[i];
      var cell = $("b" + b.pos);
      if (cell) { cell.classList.add("flash"); if (animate) await sleep(140); cell.classList.remove("flash"); cell.classList.add(b.set ? "hit" : "miss"); }
      li("i = " + b.i + ": pos = (h1 + " + b.i + "·h2) mod 2⁶⁴ mod m = <b>" + b.pos + "</b> → bit is <b>" + (b.set ? "1" : "0") + "</b>" + (b.set ? "" : " → <b>stop:</b> this bit would be 1 if the password had ever been inserted"));
      if (!b.set) { stopped = true; break; }
    }
    var v = $("verdict");
    if (data.verdict === "reject") {
      v.className = "verdict reject";
      v.innerHTML = "All " + data.sizing.k + " bits are 1 → <b>probably in the corpus → REJECTED</b>. " +
        (data.kind === "true_positive" ? "This password <em>is</em> in the list (true positive)." : "This password is <em>not</em> in the list — a <b>false positive</b>; the user simply picks another password.") +
        "<br>Validator message: “" + esc(data.validator.message) + "” <span class='pill'>code " + data.validator.code + "</span>";
    } else {
      v.className = "verdict pass";
      v.innerHTML = "Bit " + data.bits[data.first_zero].pos + " is 0 → <b>definitely not in the corpus → this layer passes</b> after " + (data.first_zero + 1) + " of " + data.sizing.k + " reads. " +
        "The password still has to clear the other validators (length, Django's common list, context terms).";
    }
    $("validator-note").textContent = (extraNote || "") + " Help text shown on the form: “" + data.validator.help_text + "”";
  }

  async function check() {
    $("check-error").textContent = "";
    if (!state.built) await build();
    var body = params(); body.probe = $("probe").value;
    try { await showCheck(await post("/accounts/simulation/api/check/", body)); }
    catch (e) { $("check-error").textContent = e.message; }
  }

  async function hunt() {
    $("check-error").textContent = "";
    if (!state.built) await build();
    var btn = $("hunt-btn"); btn.disabled = true; btn.textContent = "Searching random passwords…";
    try {
      var data = await post("/accounts/simulation/api/hunt/", params());
      if (!data.verdict) { $("check-error").textContent = "No false positive found in " + fmt(data.tries) + " random tries (expected about " + fmt(Math.round(data.expected_tries)) + ")."; return; }
      $("probe").value = data.trace.password;
      await showCheck(data, "Found after " + fmt(data.tries) + " random passwords (expected ≈ " + fmt(Math.round(data.expected_tries)) + " at this rate).");
    } catch (e) { $("check-error").textContent = e.message; }
    finally { btn.disabled = false; btn.textContent = "Find a false positive"; }
  }

  $("build-btn").addEventListener("click", build);
  $("check-btn").addEventListener("click", check);
  $("hunt-btn").addEventListener("click", hunt);
  $("probe").addEventListener("keydown", function (e) { if (e.key === "Enter") check(); });
  ["passwords", "fp"].forEach(function (id) { $(id).addEventListener("input", function () { state.built = false; }); });
})();
