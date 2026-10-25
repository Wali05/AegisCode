// expect: AEG-TAINT-XSS
window.addEventListener("message", (event) => {
  document.getElementById("out").innerHTML = event.data;
});
