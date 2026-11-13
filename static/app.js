document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy-target]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copyTarget);
  if (!target || !navigator.clipboard) return;
  try {
    await navigator.clipboard.writeText(target.textContent);
    button.textContent = "Copied";
  } catch (_) {
    button.textContent = "Copy unavailable";
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-confirm]");
  if (form && !window.confirm(form.dataset.confirm)) event.preventDefault();
});
