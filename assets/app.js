// Progressive enhancement only: every form works without JavaScript.
(() => {
  document.documentElement.classList.add("js");
  const $ = (id) => document.getElementById(id);
  const BLOCK_RE = /#([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
  const HELP = "A Notion: menú del bloc ⋮⋮ → <i>Copia l'enllaç al bloc</i>.";

  const url = $("url");
  const hint = $("urlHint");
  const checkUrl = () => {
    if (!url) return true;
    const v = url.value.trim();
    if (!v) { url.classList.remove("invalid"); hint.className = "hint"; hint.innerHTML = HELP; return false; }
    const m = v.match(BLOCK_RE);
    const notion = /^https:\/\/([a-z0-9-]+\.)*notion\.(so|com|site)\//i.test(v);
    if (!notion || !m) {
      url.classList.add("invalid"); hint.className = "hint err";
      hint.textContent = !notion ? "Ha de ser un enllaç https de notion.so o notion.com."
        : "Falta l'identificador del bloc (#…). Copia l'enllaç al bloc, no a la pàgina.";
      return false;
    }
    url.classList.remove("invalid"); hint.className = "hint";
    const id = m[1].replace(/-/g, "").toLowerCase();
    hint.textContent = "Bloc detectat ";
    const chip = document.createElement("span");
    chip.className = "chip"; chip.textContent = `${id.slice(0, 8)}…${id.slice(-4)}`;
    hint.append(chip);
    return true;
  };
  if (url) { url.addEventListener("input", checkUrl); if (url.value) checkUrl(); }

  // Expiry: show the date picker only for "date"; send it as UTC ISO.
  const date = $("date");
  const syncDate = () => {
    const sel = document.querySelector("input[name=ttl]:checked");
    if (date) date.hidden = !(sel && sel.value === "date");
  };
  document.querySelectorAll("input[name=ttl]").forEach((r) => r.addEventListener("change", syncDate));
  syncDate();

  const form = $("f");
  if (form) form.addEventListener("submit", (e) => {
    if (!checkUrl()) { e.preventDefault(); url.focus(); return; }
    const sel = document.querySelector("input[name=ttl]:checked");
    if (sel && sel.value === "date") {
      if (!date.value) { e.preventDefault(); date.focus(); return; }
      $("date_utc").value = new Date(date.value).toISOString().replace(/\.\d{3}Z$/, "Z");
    }
    const b = $("go"); b.disabled = true; b.textContent = "Generant…";
  });

  // Copy buttons.
  document.querySelectorAll(".copy").forEach((btn) => btn.addEventListener("click", async () => {
    const el = $(btn.dataset.t);
    try { await navigator.clipboard.writeText(el.textContent); }
    catch {
      const r = document.createRange(); r.selectNodeContents(el);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand("copy"); s.removeAllRanges();
    }
    btn.textContent = "Copiat"; btn.classList.add("done");
    setTimeout(() => { btn.textContent = "Copia"; btn.classList.remove("done"); }, 1500);
  }));

  // Show dates in the viewer's local time.
  document.querySelectorAll("[data-ts]").forEach((el) => {
    const d = new Date(Number(el.dataset.ts) * 1000);
    el.textContent = d.toLocaleString("ca", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
  });
})();
