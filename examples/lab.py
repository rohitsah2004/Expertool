"""Deliberately weak, loopback-only fixture. Never deploy this application."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os


class Lab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        owner = self.headers.get('Authorization') == 'Bearer lab-owner'
        other = self.headers.get('Authorization') == 'Bearer lab-other'
        status, body = 200, '<title>Expertool local lab</title><a href="/next">Next page</a><a href="/protected">Account page</a><a href="/redirect">Redirect</a>'
        if self.path == '/next':
            body = '<title>Next page</title><form action="/never-submit" method="post"><input name="test"></form>'
        elif self.path == '/protected':
            status, body = (200, '<title>Account page</title>Owned test account') if owner else (401, 'Authentication required')
        elif self.path == '/.git/config':
            body = '[core]\nrepositoryformatversion = 0\nbare = false\n# Synthetic local exposure fixture, no repository data\n'
        elif self.path == '/marker':
            body = 'EXPERTOOL_FIXTURE_MARKER'
        elif self.path == '/private-canary':
            # Intentional account-boundary failure. FIX_BOUNDARY=1 simulates remediation.
            if owner or (other and os.environ.get('FIX_BOUNDARY') != '1'):
                body = 'EXPERTOOL_OWNED_CANARY_2026'
            else:
                status, body = 403, 'Forbidden'
        elif self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://out-of-scope.invalid/')
            self.end_headers()
            return
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Set-Cookie', 'lab_fixture=non-sensitive; Path=/')
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 8901), Lab)
    print('Deliberately weak lab: http://127.0.0.1:8901 (loopback only)', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
