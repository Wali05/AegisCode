// expect: none
const h = location.hash.slice(1);
el.innerHTML = DOMPurify.sanitize(h);
