/* Kredit & donasi. Berdiri sendiri (tanpa innerHTML), kompatibel CSP script-src 'self'. */
(function () {
  "use strict";
  var REK = "103795214092";
  var BANKS = [
    { n: "Bank Jago",     pkg: "com.jago.digitalBanking", web: "https://www.jago.com" },
    { n: "BSI",           pkg: "com.bsm.activity2",       web: "https://www.bankbsi.co.id" },
    { n: "Mandiri",       pkg: "id.bmri.livin",           web: "https://bankmandiri.co.id" },
    { n: "BRI",           pkg: "id.co.bri.brimo",         web: "https://bri.co.id" },
    { n: "BNI",           pkg: "src.com.bni",             web: "https://www.bni.co.id" },
    { n: "BCA",           pkg: "com.bca",                 web: "https://www.bca.co.id" },
    { n: "Muamalat",      pkg: "",                        web: "https://www.bankmuamalat.co.id" }
  ];
  var dlg = document.getElementById("donasi");
  if (!dlg) return;

  function toast(msg) {
    var box = document.getElementById("toasts");
    if (!box) return;
    var t = document.createElement("div");
    t.className = "toast"; t.setAttribute("role", "status"); t.textContent = msg;
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 3200);
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return legacy(text); });
    }
    return Promise.resolve(legacy(text));
  }
  function legacy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", "");
      ta.style.cssText = "position:fixed;top:-100px;opacity:0";
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch (e) { return false; }
  }

  var isAndroid = /Android/i.test(navigator.userAgent);

  function openBank(b) {
    copy(REK).then(function (ok) {
      if (!ok) { toast("Gagal menyalin otomatis. Nomor rekening: " + REK); return; }
      if (isAndroid && b.pkg) {
        toast("Nomor rekening disalin. Membuka " + b.n + "…");
        var fb = encodeURIComponent(b.web);
        setTimeout(function () {
          window.location.href = "intent://#Intent;package=" + b.pkg + ";S.browser_fallback_url=" + fb + ";end";
        }, 350);
      } else if (isAndroid) {
        toast("Nomor rekening disalin. Silakan buka aplikasi " + b.n + " Anda.");
      } else {
        toast("Nomor rekening disalin. Tempel di aplikasi/internet banking " + b.n + ".");
      }
    });
  }

  var list = document.getElementById("don-banks");
  BANKS.forEach(function (b) {
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "bank";
    btn.textContent = b.n;
    btn.addEventListener("click", function () { openBank(b); });
    list.appendChild(btn);
  });

  document.getElementById("don-copy").addEventListener("click", function () {
    copy(REK).then(function (ok) { toast(ok ? "Nomor rekening disalin" : "Gagal menyalin. Nomor: " + REK); });
  });
  document.getElementById("btn-donasi").addEventListener("click", function () {
    dlg.showModal();
    requestAnimationFrame(function () { dlg.setAttribute("data-open", ""); });
  });
  function close() {
    dlg.removeAttribute("data-open");
    setTimeout(function () { if (dlg.open) dlg.close(); }, 200);
  }
  dlg.querySelector("[data-close]").addEventListener("click", close);
  dlg.addEventListener("cancel", function () { dlg.removeAttribute("data-open"); });
  dlg.addEventListener("click", function (e) { if (e.target === dlg) close(); });
})();
