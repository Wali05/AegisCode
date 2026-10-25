// expect: none
const params = new URLSearchParams(location.search);
document.getElementById("banner").textContent = "Welcome " + params.get("user");
