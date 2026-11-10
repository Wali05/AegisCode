// expect: none
window.addEventListener("message", (e) => {
  if (e.origin !== "https://app.example.com") return;
  el.innerHTML = e.data;
});
