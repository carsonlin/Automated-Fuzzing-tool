"""A tiny, deliberately-vulnerable test server for the fuzzer to target.

Stdlib only -- run with `python tests/server.py`, then point the fuzzer at
http://localhost:8000/. It exists so we can exercise the submit + analyze
stages offline against realistic (broken) behavior:

  - GET  /        -> a login form
  - POST /login   -> processes input with INTENTIONAL bugs:
      * a single quote (') triggers a fake SQL error + HTTP 500   (SQLi signal)
      * input is reflected unescaped into the response            (XSS signal)
      * a very long value triggers a 500                          (overflow signal)

This is for local testing ONLY. Never expose it.
"""

import http.server
import urllib.parse

FORM_HTML = """<!doctype html>
<html><body>
  <h1>Login</h1>
  <form action="/login" method="post">
    <label for="u">Username</label>
    <input type="text" id="u" name="username">
    <label for="p">Password</label>
    <input type="password" id="p" name="password" maxlength="64">
    <label for="e">Email</label>
    <input type="email" id="e" name="email">
    <label for="a">Age</label>
    <input type="number" id="a" name="age">
    <label for="c">Comments</label>
    <textarea name="comments"></textarea>
    <button type="submit" name="action" value="login">Log in</button>
  </form>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond(200, FORM_HTML)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        fields = urllib.parse.parse_qs(raw)
        values = [v for vals in fields.values() for v in vals]

        # --- Intentional vulnerabilities, for the analyzer to catch ---
        for v in values:
            if "'" in v:  # naive SQL: an unescaped quote "breaks" the query
                return self._respond(
                    500,
                    "<h1>Server Error</h1><pre>"
                    "SQL syntax error near '%s' in query "
                    "SELECT * FROM users WHERE name='%s'</pre>" % (v, v),
                )
            if len(v) > 1000:  # no length guard -> crash on huge input
                return self._respond(500, "<h1>Server Error</h1><pre>"
                                          "Internal error: input too large</pre>")

        # Reflect input unescaped -> stored/reflected XSS
        reflected = " ".join(values)
        self._respond(200, "<h1>Welcome %s</h1>" % reflected)

    def _respond(self, status, body):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass  # quiet


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", 8000), Handler)
    print("test server on http://127.0.0.1:8000/  (Ctrl-C to stop)")
    server.serve_forever()
