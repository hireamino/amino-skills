"""Deterministic socket/TLS seam for exercising the shipping HTTP functions."""

import re


_OMIT = object()


def http_response(status, body="", content_type=_OMIT, headers=None):
    """Build the raw HTTP/1.1 bytes consumed by audit.py's socket readers."""
    lines = [f"HTTP/1.1 {status} Fixture"]
    if content_type is not _OMIT:
        lines.append(f"Content-Type: {content_type}")
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode()


class _RawConnection:
    def __init__(self, endpoint):
        self.endpoint = endpoint


class _TlsSocket:
    def __init__(self, fixture, endpoint, server_hostname, response):
        self.fixture = fixture
        self.endpoint = endpoint
        self.server_hostname = server_hostname
        self.response = response if isinstance(response, bytes) else b""
        self.read_error = response if isinstance(response, Exception) else None
        self.offset = 0
        self.request_sent = False

    def sendall(self, request):
        text = request.decode("iso-8859-1")
        lines = text.split("\r\n")
        request_line = lines[0]
        hosts = [
            line.split(":", 1)[1].strip()
            for line in lines[1:]
            if line.lower().startswith("host:")
        ]
        if hosts != [self.server_hostname]:
            raise AssertionError(
                f"HTTP Host header {hosts!r} does not match TLS SNI {self.server_hostname!r}"
            )
        self.fixture.requests.append({
            "endpoint": self.endpoint,
            "server_hostname": self.server_hostname,
            "request_line": request_line,
            "bytes": request,
        })
        self.request_sent = True

    def recv(self, size):
        if not self.request_sent:
            raise AssertionError("HTTP response read before request was sent")
        if self.read_error is not None:
            raise self.read_error
        chunk = self.response[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self):
        return None


class _TlsContext:
    def __init__(self, fixture, factory):
        self.fixture = fixture
        self.factory = factory

    def wrap_socket(self, connection, server_hostname):
        if not isinstance(connection, _RawConnection):
            raise AssertionError("TLS wrapper received an unknown connection object")
        self.fixture.wraps.append({
            "factory": self.factory,
            "endpoint": connection.endpoint,
            "server_hostname": server_hostname,
        })
        response = self.fixture.response_for_host(server_hostname)
        return _TlsSocket(
            self.fixture, connection.endpoint, server_hostname, response,
        )


class SocketTlsFixture:
    """Record vetted connects, TLS factories/SNI and exact HTTP request bytes."""

    def __init__(self, response_for_host):
        self.response_for_host = response_for_host
        self.connects = []
        self.contexts = []
        self.wraps = []
        self.requests = []

    def create_connection(self, endpoint, timeout):
        self.connects.append({"endpoint": endpoint, "timeout": timeout})
        if endpoint[1] != 443:
            raise OSError(f"fixture refuses non-HTTPS connection to {endpoint!r}")
        return _RawConnection(endpoint)

    def _context(self, factory):
        context = _TlsContext(self, factory)
        self.contexts.append(context)
        return context

    def create_default_context(self):
        return self._context("default")

    def create_unverified_context(self):
        return self._context("unverified")


def request_path(request_line):
    """Return the request target from a recorded GET line."""
    match = re.fullmatch(r"GET (\S+) HTTP/1\.0", request_line)
    return match.group(1) if match else None
