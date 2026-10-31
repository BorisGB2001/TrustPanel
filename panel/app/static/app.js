// Сортировка и фильтр таблицы клиентов, автообновление главной (CSP: только свои скрипты).
(function () {
  const table = document.getElementById("clients");
  if (table) {
    const body = table.tBodies[0];
    const val = (td) => td.dataset.v !== undefined ? Number(td.dataset.v) : td.textContent.trim().toLowerCase();
    table.querySelectorAll("th").forEach((th, i) => {
      th.classList.add("sort");
      th.addEventListener("click", () => {
        const dir = th.dataset.dir === "asc" ? "desc" : "asc";
        table.querySelectorAll("th").forEach((x) => delete x.dataset.dir);
        th.dataset.dir = dir;
        const rows = Array.from(body.rows);
        rows.sort((a, b) => {
          const x = val(a.cells[i]), y = val(b.cells[i]);
          const r = typeof x === "number" ? x - y : String(x).localeCompare(String(y), "ru");
          return dir === "asc" ? r : -r;
        });
        rows.forEach((r) => body.appendChild(r));
      });
    });
    const q = document.getElementById("filter"), st = document.getElementById("status-filter");
    const apply = () => {
      const text = (q.value || "").toLowerCase(), s = st.value;
      Array.from(body.rows).forEach((r) => {
        r.hidden = !(r.textContent.toLowerCase().includes(text) && (!s || r.dataset.status === s));
      });
    };
    q.addEventListener("input", apply);
    st.addEventListener("change", apply);
    // автообновление раз в минуту, если пользователь ничего не делает на странице
    let busy = 0;
    ["input", "change", "click", "keydown"].forEach((e) => document.addEventListener(e, () => { busy = Date.now(); }));
    setInterval(() => {
      if (!document.hidden && Date.now() - busy > 60000 && !document.querySelector("details[open]")) location.reload();
    }, 60000);
  }
})();

// Списки-фильтры (группа и т. п.) применяются сразу при выборе — без встроенных обработчиков из-за CSP.
document.querySelectorAll("select[data-autosubmit]").forEach((s) => s.addEventListener("change", () => s.form.submit()));

// Топ по трафику: при наведении на клиента — карточка крупно (скачано/отдано и его график за период).
(function () {
  const rows = document.querySelectorAll(".tbars [data-tip]");
  if (!rows.length) return;
  const NS = "http://www.w3.org/2000/svg";
  const tip = document.createElement("div");
  tip.className = "tip";
  tip.hidden = true;
  document.body.appendChild(tip);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  const svgEl = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };

  function chart(series) {
    const W = 300, H = 110, B = 16, n = series.length, bw = W / n;
    const top = Math.max(1, ...series.map((s) => s[1] + s[2]));
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "tip-chart" });
    series.forEach((s, i) => {
      const hd = (H - B) * s[1] / top, hu = (H - B) * s[2] / top, x = i * bw + 0.5, w = Math.max(bw - 1, 0.5);
      svg.appendChild(svgEl("rect", { class: "s1", x, y: H - B - hd, width: w, height: hd }));
      svg.appendChild(svgEl("rect", { class: "s2", x, y: H - B - hd - hu, width: w, height: hu }));
      if (i === 0 || i === n - 1 || i % Math.ceil(n / 6) === 0) {
        const t = svgEl("text", { class: "axis", x: x + w / 2, y: H - 3, "text-anchor": "middle" });
        t.textContent = s[0];
        svg.appendChild(t);
      }
    });
    return svg;
  }

  function show(a, ev) {
    const d = JSON.parse(a.getAttribute("data-tip"));
    const l = JSON.parse(a.closest("svg").getAttribute("data-labels") || "{}");
    tip.replaceChildren();
    tip.appendChild(el("div", "tip-name", d.name));
    const max = Math.max(1, d.d, d.u);
    for (const [cls, label, val, raw] of [["s1", l.down, d.down, d.d], ["s2", l.up, d.up, d.u]]) {
      const row = el("div", "tip-row");
      row.appendChild(el("span", "tip-label", label));
      const bar = el("span", "tip-bar");
      const fill = el("span", "tip-fill " + cls);
      fill.style.width = Math.max(1, 100 * raw / max) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);
      row.appendChild(el("b", "", val));
      tip.appendChild(row);
    }
    tip.appendChild(el("div", "tip-total", `${l.total}: ${d.total}`));
    if (d.series && d.series.length > 1) {
      tip.appendChild(el("div", "tip-period", l.period));
      tip.appendChild(chart(d.series));
    }
    tip.hidden = false;
    move(ev);
  }

  function move(ev) {
    const pad = 16, r = tip.getBoundingClientRect();
    let x = ev.clientX + pad, y = ev.clientY + pad;
    if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - pad;
    if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - pad;
    tip.style.left = Math.max(8, x) + "px";
    tip.style.top = Math.max(8, y) + "px";
  }

  rows.forEach((a) => {
    a.addEventListener("mouseenter", (ev) => show(a, ev));
    a.addEventListener("mousemove", move);
    a.addEventListener("mouseleave", () => { tip.hidden = true; });
  });
})();
