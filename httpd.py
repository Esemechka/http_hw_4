import socket
import os
import datetime
import mimetypes
import logging
from email.parser import Parser
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor
from optparse import OptionParser


MAX_LINE = 64*1024
MAXHEADERS = 100
INDEX_FILENAME = 'index.html'
server_name = 'example.local'


class MyHTTPServer:
    protocol_version = "HTTP/1.1"

    def __init__(self, host, port, root, workers):
        self._host = host
        self._port = port
        self.root = root
        self.workers = workers
        self._server_name = server_name
        self.serv_sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
            proto=0)
        self.request_version = ''
        self.close_connection = True

    def serve_forever(self):
        try:
            self.serv_sock.bind((self._host, self._port))
            self.serv_sock.listen()
            while True:
                conn, _ = self.serv_sock.accept()
                pool = ThreadPoolExecutor(max_workers=self.workers)
                pool.submit(self.serve_client, conn)
        finally:
            self.serv_sock.close()

    def serve_client(self, conn):
        try:
            self.close_connection = True
            req = self.parse_request(conn)
            resp = self.handle_one_request(req)
            self.send_response(conn, resp)
            while not self.close_connection:
                self.handle_one_request(req)
        except ConnectionResetError:
            conn = None
        except Exception as e:
            self.send_error(conn, e)

        if conn:
            conn.close()

    def parse_request(self, conn):
        rfile = conn.makefile('rb')
        raw = rfile.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            self.send_error(conn=conn, err='Request line is too long')

        req_line = str(raw, 'iso-8859-1')
        logging.info(f'Request line is {req_line}')
        req_line = req_line.rstrip('\r\n')

        words = req_line.split()

        if len(words) >= 3:
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split('.')
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(conn=conn, err='Bad request')
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(conn, "Invalid HTTP version (%s)" % req_line)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(conn, "Bad request syntax (%r)" % req_line)
            return False
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(conn, "Bad HTTP/0.9 request type (%r)" % command)
                return False
        ver = words[-1]
        self.request_version = ver

        method, target = words[:2]
        headers = self.parse_headers(rfile)
        if not host:
            self.send_error(conn, 'Bad request')
        return Request(method, target, ver, headers, rfile)

    def parse_headers(self, rfile):
        headers = []
        while True:
            line = rfile.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise Exception('Header line is too long')

            if line in (b'\r\n', b'\n', b''):
                break

            headers.append(line)
            if len(headers) > MAXHEADERS:
                raise Exception('Too many headers')
        hstring = b''.join(headers).decode('iso-8859-1')
        return Parser().parsestr(hstring)

    def handle_one_request(self, req):
        return self.handle_get_files(req)

    def handle_get_files(self, req):
        full_path = unquote(self.root + req.path)
        conntype = req.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False

        contentType, _ = mimetypes.guess_type(full_path)

        if not os.path.exists(full_path):
            raise HTTPError(404, 'Not_found')

        if not os.access(full_path, os.X_OK):
            raise HTTPError(403, 'Forbidden')

        if os.path.isdir(full_path):
            full_path = full_path + INDEX_FILENAME
        try:
            body = open(full_path, 'rb')
            body = body.read()
            headers = [
                ('Date', datetime.date.today()),
                ('Server', self._server_name),
                ('Content-Length', len(body)),
                ('Content-Type', contentType),
                ('Connection', conntype)
                ]
            if req.method == 'HEAD':
                return Response(200, 'OK', headers)
            elif req.method == 'GET':
                return Response(200, 'OK', headers, body)
            else:
                raise HTTPError(405, 'method_not_allowed')
        except OSError:
            raise HTTPError(404, 'Not_found')

    def send_response(self, conn, resp):
        wfile = conn.makefile('wb')
        status_line = f'{self.request_version} {resp.status} {resp.reason}\r\n'
        wfile.write(status_line.encode('iso-8859-1'))

        if resp.headers:
            for (key, value) in resp.headers:
                header_line = f'{key}: {value}\r\n'
                wfile.write(header_line.encode('iso-8859-1'))

        wfile.write(b'\r\n')
        if resp.body:
            wfile.write(resp.body)

        wfile.flush()
        wfile.close()
        conn.close()

    def send_error(self, conn, err):
        try:
            status = err.status
            reason = err.reason
            body = (err.body or err.reason).encode('utf-8')
        except:
            status = 500
            reason = b'Internal Server Error'
            body = b'Internal Server Error'
        resp = Response(status, reason,
                        [('Server', self._server_name),
                         ('Content-Length', len(body))],
                        body)
        self.send_response(conn, resp)


class Request:
    def __init__(self, method, target, version, headers, rfile):
        self.method = method
        self.target = target
        self.version = version
        self.headers = headers
        self.rfile = rfile

    @property
    def path(self):
        return self.url.path

    @property
    def query(self):
        return parse_qs(self.url.query)

    @property
    def url(self):
        return urlparse(self.target)


class Response:
    def __init__(self, status, reason, headers=None, body=None):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body


class HTTPError(Exception):
    def __init__(self, status, reason, body=None):
        super()
        self.status = status
        self.reason = reason
        self.body = body


if __name__ == '__main__':

    op = OptionParser()
    op.add_option("--host", action="store", type=str, default='localhost')
    op.add_option("-p", "--port", action="store", type=int, default='80')
    op.add_option("-r", "--root", action="store", type=str, default='./http-test-suite/')
    op.add_option("-w", "--workers", action="store", type=int, default='10')
    op.add_option("-l", "--log", action="store", default='log.txt')

    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')

    host = opts.host
    port = int(opts.port)
    workers = opts.workers
    root = opts.root

    serv = MyHTTPServer(host, port, root, workers)
    logging.info("Starting server at %s" % opts.port)
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        pass
