// expect: AEG-TAINT-XSS
const params = new URLSearchParams(location.search);
document.getElementById("banner").innerHTML = "Welcome " + params.get("user");
