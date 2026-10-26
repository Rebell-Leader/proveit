// Copy buttons: <button data-copy="#element-id">
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const source = document.querySelector(button.dataset.copy);
  if (!source) return;
  navigator.clipboard.writeText(source.innerText).then(() => {
    const label = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = label; }, 1400);
  });
});
