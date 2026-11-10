// expect: AEG-TAINT-REDIRECT
import http from "node:http";
http.createServer((req, res) => {
  const to = new URL(req.url, "http://localhost").searchParams.get("to");
  res.writeHead(302, { Location: to });
  res.end();
}).listen(3000);
