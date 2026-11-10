// expect: AEG-TAINT-XSS
const msg = new URLSearchParams(location.search).get("msg");
document.getElementById("banner").innerHTML = "<strong>" + msg + "</strong>";
