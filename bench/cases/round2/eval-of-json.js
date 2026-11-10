// expect: AEG-TAINT-CODE
window.addEventListener("message", (e) => { eval(e.data); });
