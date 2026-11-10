// expect: AEG-TAINT-REDIRECT
const target = new URLSearchParams(window.location.search).get("next");
window.location.href = target;
