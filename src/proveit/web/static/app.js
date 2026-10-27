// Copy buttons: <button data-copy="#element-id">
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.querySelector(button.dataset.copy);
  if (!source) return;
  Promise.resolve().then(() => navigator.clipboard.writeText(source.innerText)).then(() => {
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = label; }, 1400);
  }).catch(() => {
    const range = document.createRange();
    range.selectNodeContents(source);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    button.textContent = "Draft selected — copy it manually";
  });
});


// Citation targets live inside collapsed evidence panels. Open the path before scrolling.
function revealCitation() {
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  if (!id.startsWith("L-")) return;
  const target = document.getElementById(id);
  if (!target) return;
  for (let node = target.parentElement; node; node = node.parentElement) {
    if (node.tagName === "DETAILS") node.open = true;
  }
  target.scrollIntoView({ block: "center", behavior: "instant" });
}
window.addEventListener("hashchange", revealCitation);
document.addEventListener("click", (event) => {
  const link = event.target.closest('a[href^="#L-"]');
  if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  history.pushState(null, "", link.getAttribute("href"));
  revealCitation();
});
revealCitation();
