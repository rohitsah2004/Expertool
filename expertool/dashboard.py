"""Loopback-only review UI using the existing workspace database."""
import json
import secrets
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .workspace import Workspace, markdown_report

STATIC = Path(__file__).with_name('static')


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, db_path, port=8765):
        self.db_path = str(Path(db_path).resolve())
        self.token = secrets.token_urlsafe(32)
        # Initialize schema before serving; each request uses its own connection.
        workspace = Workspace(self.db_path)
        workspace.close()
        super().__init__(('127.0.0.1', port), DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Do not log program names, query strings, or evidence.
        pass

    def send_content(self, status, body, content_type='application/json; charset=utf-8', download=False):
        if not isinstance(body, bytes):
            body = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if download:
            self.send_header('Content-Disposition', 'attachment; filename="assessment.md"')
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status, data):
        self.send_content(status, json.dumps(data))

    def trusted_request(self, mutation=False):
        port = self.server.server_port
        hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
        host = self.headers.get('Host', '')
        if host not in hosts or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.json_response(403, {'error': 'Local same-origin access required'})
            return False
        origin = self.headers.get('Origin')
        if origin is not None and origin != 'http://' + host:
            self.json_response(403, {'error': 'Origin mismatch'})
            return False
        if mutation and (origin != 'http://' + host or not secrets.compare_digest(self.headers.get('X-Expertool-Token', ''), self.server.token)):
            self.json_response(403, {'error': 'Review token and same origin required'})
            return False
        return True

    def do_GET(self):
        if not self.trusted_request():
            return
        parsed = urlsplit(self.path)
        static = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if parsed.path in static:
            name, content_type = static[parsed.path]
            self.send_content(200, (STATIC / name).read_bytes(), content_type)
            return
        if parsed.path == '/api/session':
            self.json_response(200, {'token': self.server.token})
            return
        if parsed.path not in {'/api/programs', '/api/snapshot', '/api/report'}:
            self.json_response(404, {'error': 'Not found'})
            return
        workspace = Workspace(self.server.db_path)
        try:
            if parsed.path == '/api/programs':
                rows = workspace.db.execute('''SELECT p.name,
                    (SELECT count(*) FROM assets a WHERE a.program=p.name) AS assets,
                    (SELECT count(*) FROM findings f JOIN assets a ON a.id=f.asset
                     WHERE a.program=p.name AND f.state='candidate') AS candidates
                    FROM programs p ORDER BY p.name''')
                self.json_response(200, [dict(row) for row in rows])
            else:
                values = parse_qs(parsed.query).get('program', [])
                if len(values) != 1:
                    raise ValueError('Select one program')
                snapshot = workspace.snapshot(values[0])
                if parsed.path == '/api/report':
                    self.send_content(200, markdown_report(snapshot), 'text/markdown; charset=utf-8', download=True)
                else:
                    self.json_response(200, snapshot)
        except ValueError as error:
            self.json_response(400, {'error': str(error)})
        except sqlite3.Error:
            self.json_response(500, {'error': 'Workspace could not be read; retry after current import completes'})
        finally:
            workspace.close()

    def do_POST(self):
        if not self.trusted_request(mutation=True):
            return
        if self.path != '/api/review':
            self.json_response(404, {'error': 'Not found'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096 or self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise ValueError('Expected a small JSON request')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or type(data.get('id')) is not int or not isinstance(data.get('program'), str):
                raise ValueError('Finding ID and program required')
            workspace = Workspace(self.server.db_path)
            try:
                row = workspace.db.execute('''SELECT f.id FROM findings f JOIN assets a ON a.id=f.asset
                    WHERE f.id=? AND a.program=?''', (data['id'], data['program'])).fetchone()
                if row is None:
                    raise ValueError('Finding does not belong to this program')
                workspace.review(data['id'], data.get('state'))
            finally:
                workspace.close()
            self.json_response(200, {'ok': True})
        except (ValueError, TypeError) as error:
            self.json_response(400, {'error': str(error)})
        except sqlite3.Error:
            self.json_response(500, {'error': 'Review could not be saved; retry'})


def serve(db_path, port):
    server = DashboardServer(db_path, port)
    print(f'Expertool dashboard: http://127.0.0.1:{server.server_port}', flush=True)
    print('Press Ctrl+C to stop.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
