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
