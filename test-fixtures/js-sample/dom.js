// Deliberate insecure browser sample. Not a real application.

const params = new URLSearchParams(location.search);
const next = params.get("next");
document.getElementById("out").innerHTML = next;
el.insertAdjacentHTML("beforeend", next);
location.href = next;
window.addEventListener("message", function (event) {
  event.source.postMessage(event.data, "*");
});
localStorage.setItem("token", next);
user.__proto__ = JSON.parse(next);
new WebSocket(next);
eval(next);
