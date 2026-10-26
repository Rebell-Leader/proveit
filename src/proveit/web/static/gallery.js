// Report gallery filters, client-side so they work on the static site too. State lives in the query string.
(() => {
  const rows = [...document.querySelectorAll("#gallery tbody tr[data-truth]")];
  const empty = document.querySelector("#no-match");
  const state = { show: "all", verdict: "all" };
  const params = new URLSearchParams(location.search);
  if (["all", "slop", "valid"].includes(params.get("show"))) state.show = params.get("show");
  if (params.get("verdict")) state.verdict = params.get("verdict");

  function apply() {
    let shown = 0;
    for (const row of rows) {
      const ok = (state.show === "all" || row.dataset.truth === state.show)
        && (state.verdict === "all" || row.dataset.final === state.verdict);
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
    const query = new URLSearchParams();
    if (state.show !== "all") query.set("show", state.show);
    if (state.verdict !== "all") query.set("verdict", state.verdict);
    history.replaceState(null, "", `${location.pathname}${query.toString() ? "?" + query : ""}#reports`);
    apply();
  }));
  apply();
})();
