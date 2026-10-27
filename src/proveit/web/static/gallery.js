// Report gallery filters, client-side so they work on the static site too. State lives in the query string.
(() => {
  const rows = [...document.querySelectorAll("#gallery tbody tr[data-truth]")];
  const empty = document.querySelector("#no-match");
  const state = { show: "all", verdict: "all", q: "" };
  const search = document.querySelector("#report-search");
  const params = new URLSearchParams(location.search);
  if (params.size || location.hash === "#reports") document.querySelector(".collection").open = true;
  if (["all", "slop", "valid"].includes(params.get("show"))) state.show = params.get("show");
  if (params.get("verdict")) {
    state.verdict = params.get("verdict");
    document.querySelector(".verdict-filters").open = true;
  }
  state.q = params.get("q") || "";
  search.value = state.q;

  function apply() {
    let shown = 0;
    for (const row of rows) {
      const ok = (state.show === "all" || row.dataset.truth === state.show)
        && (state.verdict === "all" || row.dataset.final === state.verdict)
        && row.dataset.search.toLocaleLowerCase().includes(state.q.toLocaleLowerCase().trim());
      row.classList.toggle("hidden", !ok);
      shown += ok;
    }
    empty.classList.toggle("hidden", shown > 0);
    document.querySelectorAll("[data-show]").forEach((a) => a.classList.toggle("on", a.dataset.show === state.show));
    document.querySelectorAll("[data-verdict]").forEach((a) => a.classList.toggle("on", a.dataset.verdict === state.verdict));
  }

  document.querySelectorAll("[data-show], [data-verdict]").forEach((a) => a.addEventListener("click", (event) => {
    event.preventDefault();
    if (a.dataset.show) state.show = a.dataset.show;
    if (a.dataset.verdict) state.verdict = a.dataset.verdict;
    syncQuery();
    apply();
  }));

  function syncQuery() {
    const query = new URLSearchParams();
    if (state.show !== "all") query.set("show", state.show);
    if (state.verdict !== "all") query.set("verdict", state.verdict);
    if (state.q) query.set("q", state.q);
    history.replaceState(null, "", `${location.pathname}${query.toString() ? "?" + query : ""}#reports`);
  }

  search.addEventListener("input", () => {
    state.q = search.value;
    syncQuery();
    apply();
  });
  apply();
})();
