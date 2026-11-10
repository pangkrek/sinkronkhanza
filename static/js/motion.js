/* SinkronKhanza: lapisan motion. Berdiri sendiri; tidak menyentuh logika aplikasi. CSP: script-src 'self'. */
(function () {
  "use strict";
  var reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) return;
  var root = document.documentElement;
  root.classList.add("mo");
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

  /* Judul: pecah jadi huruf */
  var h1 = $(".brand h1");
  if (h1 && !h1.querySelector(".mo-ch")) {
    var txt = h1.textContent; h1.setAttribute("aria-label", txt); h1.textContent = "";
    h1.classList.add("mo-split");
    Array.prototype.forEach.call(txt, function (c, i) {
      if (c === " ") { var sp = document.createElement("span"); sp.className = "mo-sp"; sp.setAttribute("aria-hidden", "true"); h1.appendChild(sp); return; }
      var o = document.createElement("span"); o.className = "mo-ch"; o.setAttribute("aria-hidden", "true");
      var n = document.createElement("i"); n.style.setProperty("--i", i); n.textContent = c; o.appendChild(n); h1.appendChild(o);
    });
  }

  /* Muncul saat scroll */
  var targets = [".block-head", ".pair", ".role-line", ".checks", "#btn-compare", "#triage", "#triage-legend", ".toolbar", "footer p", ".credit"];
  var io = "IntersectionObserver" in window ? new IntersectionObserver(function (es) {
    es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
  }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" }) : null;
  var seq = 0;
  targets.forEach(function (sel) {
    $$(sel).forEach(function (el) {
      if (el.hasAttribute("data-reveal")) return;
      el.setAttribute("data-reveal", ""); el.style.setProperty("--d", ((seq++ % 4) * 90) + "ms");
      if (io) io.observe(el); else el.classList.add("in");
    });
  });

  /* Sorotan kartu mengikuti kursor (hanya saat di atas kartu; dibatasi per frame) */
  var pend = null, sched = false;
  document.addEventListener("pointermove", function (e) {
    var card = e.target.closest && e.target.closest(".conn, .credit");
    if (!card) return;
    pend = { card: card, x: e.clientX, y: e.clientY };
    if (!sched) { sched = true; requestAnimationFrame(function () {
      sched = false; if (!pend) return;
      var r = pend.card.getBoundingClientRect();
      pend.card.style.setProperty("--mx", (pend.x - r.left) + "px"); pend.card.style.setProperty("--my", (pend.y - r.top) + "px"); pend = null;
    }); }
  }, { passive: true });

  /* Progres scroll di stepper */
  var ticking = false;
  function prog() {
    var max = document.documentElement.scrollHeight - innerHeight, st = $(".steps");
    if (st) st.style.setProperty("--p", max > 0 ? Math.min(1, scrollY / max).toFixed(3) : 0); ticking = false;
  }
  addEventListener("scroll", function () { if (!ticking) { ticking = true; requestAnimationFrame(prog); } }, { passive: true });
  prog();

  /* Garis EKG pada tombol bandingkan: pathLength agar bisa digambar */
  $$(".launch > svg:not(.launch-ekg) path").forEach(function (p) { p.setAttribute("pathLength", "1"); });

  /* Jeda animasi saat tab disembunyikan */
  document.addEventListener("visibilitychange", function () { root.classList.toggle("mo-paused", document.hidden); });

  /* Kilatan pada bank yang diklik */
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest(".bank");
    if (b) { b.classList.remove("copied"); void b.offsetWidth; b.classList.add("copied"); }
  });

  /* Konfeti: dipicu oleh app.js lewat event "sk:celebrate" */
  var COLORS = ["#6cc8ff", "#1688c9", "#ffcf5a", "#12936b", "#6a4bd6", "#c2385a", "#ffffff"];
  function confetti(x, y) {
    var cv = document.createElement("canvas"); cv.className = "mo-confetti"; cv.setAttribute("aria-hidden", "true");
    var dpr = Math.min(devicePixelRatio || 1, 2), W = innerWidth, H = innerHeight;
    cv.width = W * dpr; cv.height = H * dpr; document.body.appendChild(cv);
    var c = cv.getContext("2d"); c.setTransform(dpr, 0, 0, dpr, 0, 0);
    var ps = [], N = 150;
    for (var i = 0; i < N; i++) {
      var a = -Math.PI / 2 + (Math.random() - .5) * 2.2, v = 7 + Math.random() * 11;
      ps.push({ x: x, y: y, vx: Math.cos(a) * v, vy: Math.sin(a) * v, r: 3 + Math.random() * 5, rot: Math.random() * 6, vr: (Math.random() - .5) * .4,
        col: COLORS[i % COLORS.length], ring: i % 9 === 0, life: 1 });
    }
    var t0 = performance.now(), last = t0;
    (function f(now) {
      var dt = Math.min(2, (now - last) / 16.7); last = now;
      c.clearRect(0, 0, W, H); var alive = 0;
      ps.forEach(function (p) {
        p.vy += 0.34 * dt; p.vx *= 0.992; p.x += p.vx * dt; p.y += p.vy * dt; p.rot += p.vr * dt; p.life -= 0.0045 * dt;
        if (p.life <= 0 || p.y > H + 30) return; alive++;
        c.globalAlpha = Math.max(0, Math.min(1, p.life * 1.6)); c.fillStyle = c.strokeStyle = p.col;
        c.save(); c.translate(p.x, p.y); c.rotate(p.rot);
        if (p.ring) { c.lineWidth = 2; c.beginPath(); c.arc(0, 0, p.r * 1.4, 0, 6.283); c.stroke(); } else c.fillRect(-p.r, -p.r / 2, p.r * 2, p.r);
        c.restore();
      });
      if (alive && now - t0 < 4200) requestAnimationFrame(f); else cv.remove();
    })(t0);
  }
  document.addEventListener("sk:celebrate", function () { confetti(innerWidth / 2, innerHeight * 0.62); });
})();
