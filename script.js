(() => {
  "use strict";

  const button = document.getElementById("modeButton");
  const panel = document.getElementById("detailPanel");

  if (!button || !panel) return;

  button.addEventListener("click", () => {
    const isOpen = button.getAttribute("aria-expanded") === "true";
    button.setAttribute("aria-expanded", String(!isOpen));
    button.textContent = isOpen ? "더 자세히 보기" : "간단히 접기";
    panel.hidden = isOpen;
    if (!isOpen) panel.focus?.();
  });
})();
