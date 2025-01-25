# Place your imports here
import signal
from optparse import OptionParser
import sys
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from enum import Enum
import re
import logging
from threading import Thread, Lock
from datetime import datetime

# Constants
BUF_SIZE = 4096
MAX_QUEUED_CONNECTIONS = 10

# Regex used for parsing
# TODO: Improve regex (the /.* is not ideal)
REQUEST_LINE_RE = re.compile(
    rb"(GET|HEAD|POST) http://([a-zA-Z\.]+)(:[0-9]+)?(/.*) HTTP/1\.0\r\n"
)
# TODO: Is the key regex correct?
HEADERS_RE = re.compile(
    rb"([A-Za-z0-9-_.~]+)*: ([A-Za-z0-9\-_.~!#$&'()*+,/:;=?@[\] ]+)\r\n"
)

# Responses for invalid requests
BAD_REQUEST_RESPOSE_LINE: bytes = b"HTTP/1.0 400 Bad Request\r\n"
NOT_IMPL_RESPOSE_LINE: bytes = b"HTTP/1.0 501 Not Implemented\r\n"
OK_RESPOSE_LINE: bytes = b"HTTP/1.0 200 OK\r\n"
FORBIDDEN_RESPOSE_LINE: bytes = b"HTTP/1.0 403 Forbidden\r\n"
NOT_MODIFED_RESPOSE_LINE: bytes = b"HTTP/1.0 304 Not Modified\r\n"

# Variables used to block specific URLs
FILTER_LOCK: Lock = Lock()
FILTER_ACTIVE: bool = False
FILTER_PATTERNS: set[str] = set()

# Variables used for caching
CACHE_LOCK: Lock = Lock()
CACHE_ACTIVE: bool = False
# Maps (host, port, path) to (response, timestamp of when response was received)
CACHE: dict[tuple[str, int, str], tuple[bytes, datetime]] = {}


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# Defines the different possible error cases when parsing an HTTP request
class ParseError(Enum):
    NOTIMPL = 1
    BADREQ = 2


# Parses the given bytes as a http request.
# Return an error or a tuple of (Host, Port, Path, Headers)
def parse_request(
    message: bytes,
) -> ParseError | tuple[str, int, str, dict[str, str]]:
    logging.debug(f"Parsing request:\n{message}")
    match = REQUEST_LINE_RE.match(message)
    if match == None:
        logging.debug("Requst did not match regex")
        return ParseError.BADREQ
    method = match.group(1)

    if method != b"GET":
        logging.debug(f"Expected GET header found {method}")
        return ParseError.NOTIMPL

    host = match.group(2).decode()
    assert isinstance(host, str)

    # Remove the : from the port
    port = int((match.group(3) or ":80")[1:])
    assert isinstance(port, int)

    path = match.group(4).decode()
    assert isinstance(path, str)

    headers: dict[str, str] = {}
    assert match.start() == 0

    rest = message[match.end() :]
    logging.debug(f"Parsing headers:\n{rest}")

    while rest != b"\r\n":
        header_match = HEADERS_RE.match(rest)
        if header_match is None:
            logging.debug(f"Could not match header: {rest}")
            return ParseError.BADREQ

        key = header_match.group(1).decode()
        assert isinstance(key, str)

        value = header_match.group(2).decode()
        assert isinstance(value, str)

        headers[key] = value
        rest = rest[header_match.end() :]

    assert rest == b"\r\n"

    logging.debug("Done Parsing")
    logging.debug(f"Host = {host}")
    logging.debug(f"Port = {port}")
    logging.debug(f"Path = {path}")
    logging.debug(f"Headers = {headers}")
    return (host, port, path, headers)


# Creates an HTTP request in a bytes object using the given info
def generate_http_request(
    host: str,
    port: int,
    path: str,
    headers: dict[str, str],
    cached: tuple[bytes, datetime] | None,
) -> bytes:
    req = bytearray()
    req.extend(f"GET {path} HTTP/1.0\r\n".encode())
    req.extend(f"Host: {host}:{port}\r\n".encode())
    req.extend(f"Connection: close\r\n".encode())

    if cached:
        # Date in form: <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
        http_date = cached[1].strftime("%a, %d %b %Y %H:%M:%S GMT")
        req.extend(f"If-Modified-Since: {http_date}\r\n".encode())

    else:
        for key, value in headers.items():
            if key == "Connection":
                continue
            req.extend(f"{key}: {value}\r\n".encode())

    req.extend("\r\n".encode())

    return bytes(req)


# Handles a built in request that is used for controlling the cache and the block-list
#
# path: A string containing the path of the request.
#
# returns: True if the request was a built in, False if not
def handle_builtin(path: str) -> bool:
    global CACHE_ACTIVE
    global FILTER_ACTIVE
    if path == "/proxy/cache/enable":
        CACHE_LOCK.acquire()
        CACHE_ACTIVE = True
        CACHE_LOCK.release()
    elif path == "/proxy/cache/disable":
        CACHE_LOCK.acquire()
        CACHE_ACTIVE = False
        CACHE_LOCK.release()
    elif path == "/proxy/cache/flush":
        CACHE_LOCK.acquire()
        CACHE.clear()
        CACHE_LOCK.release()
    elif path == "/proxy/blocklist/enable":
        FILTER_LOCK.acquire()
        FILTER_ACTIVE = True
        FILTER_LOCK.release()

    elif path == "/proxy/blocklist/disable":
        FILTER_LOCK.acquire()
        FILTER_ACTIVE = False
        FILTER_LOCK.release()

    elif path.startswith("/proxy/blocklist/add/"):
        pattern = path[len("/proxy/blocklist/add/") :]
        logging.debug("Adding filter %s", pattern)
        FILTER_LOCK.acquire()
        FILTER_PATTERNS.add(pattern)
        FILTER_LOCK.release()

    elif path.startswith("/proxy/blocklist/remove/"):
        pattern = path[len("/proxy/blocklist/remove/") :]
        logging.debug("Removing filter %s", pattern)
        FILTER_LOCK.acquire()
        FILTER_PATTERNS.discard(pattern)
        FILTER_LOCK.release()

    elif path == "/proxy/blocklist/flush":
        FILTER_LOCK.acquire()
        FILTER_PATTERNS.clear()
        FILTER_LOCK.release()

    else:
        logging.debug("Path %s not built-in", path)
        return False

    logging.debug("Path %s is built-in", path)
    return True


# Handles a client request and sends it a response
def handle_client(client_skt: socket):
    try:
        req = bytearray()

        # TODO: is somewhat slow to check the whole buffer. We could just check the end
        while b"\r\n\r\n" not in req:
            new_bytes = client_skt.recv(BUF_SIZE)
            if len(new_bytes) == 0:
                return
            req.extend(new_bytes)

        logging.debug("Parsing Request")
        parsed = parse_request(bytes(req))

        # Send the proper response if there is an error
        if isinstance(parsed, ParseError):
            if parsed == ParseError.NOTIMPL:
                logging.debug("Error: Not Implemented")
                client_skt.sendall(NOT_IMPL_RESPOSE_LINE + b"\r\n")
            elif parsed == ParseError.BADREQ:
                logging.debug("Error: Bad Request")
                client_skt.sendall(BAD_REQUEST_RESPOSE_LINE + b"\r\n")
            return

        (host, port, path, headers) = parsed

        if handle_builtin(path):
            client_skt.sendall(OK_RESPOSE_LINE + b"\r\n")
            return

        FILTER_LOCK.acquire()
        # TODO: should I add the port in this way or not?
        host_with_port = host + ":" + str(port)
        blocked = FILTER_ACTIVE and any(p in host_with_port for p in FILTER_PATTERNS)
        FILTER_LOCK.release()
        logging.debug("Host: %s %s bloked", host, ("is" if blocked else "is not"))
        if blocked:
            logging.debug("Sending 403 Forbin For blocked host: %s", host)
            client_skt.sendall(FORBIDDEN_RESPOSE_LINE + b"\r\n")
            return

        CACHE_LOCK.acquire()
        cache_active = CACHE_ACTIVE
        if cache_active:
            cached = CACHE.get((host, port, path))
        else:
            cached = None
        CACHE_LOCK.release()

        logging.debug(f"Cache active = {cache_active}, cached = {cached}")

        http_message = generate_http_request(host, port, path, headers, cached)

        # Create the socket for the server
        with socket(AF_INET, SOCK_STREAM) as server_skt:
            server_skt.connect((host, port))
            logging.debug(f"Sending message to server:\n{http_message}")
            now = datetime.now()
            server_skt.sendall(http_message)
            logging.debug(f"Sent message")

            # Send a normal request if the cache is off or the item in not cached
            if not cache_active or cached is None:
                resp = bytearray()
                resp_part = server_skt.recv(BUF_SIZE)
                resp.extend(resp_part)
                while len(resp_part) != 0:
                    logging.debug(f"Sending response to client:\n{resp_part}")
                    client_skt.sendall(resp_part)
                    resp_part = server_skt.recv(BUF_SIZE)
                    resp.extend(resp_part)

                logging.debug(f"Done sending request")
                if cache_active:
                    CACHE_LOCK.acquire()
                    logging.debug(
                        f"CACHING host = {host}, port = {port}, path = {path} now = {now}\n resp = {resp}"
                    )
                    CACHE[(host, port, path)] = (bytes(resp), now)
                    CACHE_LOCK.release()

            # If we have cached the object then look for a 304 or a 200 response
            elif cached is not None:
                logging.debug("Waiting for conditional get respose")
                resp = bytearray()
                resp_part = server_skt.recv(BUF_SIZE)
                logging.debug(f"Got part {resp_part}")
                resp.extend(resp_part)
                while len(resp_part) != 0:
                    resp_part = server_skt.recv(BUF_SIZE)
                    logging.debug(f"Got part {resp_part}")
                    resp.extend(resp_part)

                resp_as_bytes = bytes(resp)

                logging.debug(f"Response from conditional get:\n{resp_as_bytes}")

                if resp_as_bytes.startswith(NOT_MODIFED_RESPOSE_LINE):
                    logging.debug(f"Got 304 sending cached = {cached[0]}")
                    client_skt.sendall(cached[0])
                else:
                    logging.debug(f"Got 200 sending recived = {resp_as_bytes}")
                    client_skt.sendall(resp_as_bytes)
                    CACHE_LOCK.acquire()
                    CACHE[(host, port, path)] = (resp_as_bytes, now)
                    CACHE_LOCK.release()

            else:
                assert False, "Code should be unreachable"

    except Exception as e:
        logging.error(f"Exception: {e}")

    # Make sure to close the socket
    finally:
        client_skt.close()


# Start of program execution

# Set log level as appropriate
logging.basicConfig(level=logging.INFO)

# Parse out the command line server address and port number to listen to
parser = OptionParser()
parser.add_option("-p", type="int", dest="serverPort")
parser.add_option("-a", type="string", dest="serverAddress")
(options, args) = parser.parse_args()

port = options.serverPort
address = options.serverAddress
if address is None:
    address = "localhost"
if port is None:
    port = 2100

logging.info("Staring Proxy")
logging.info("Port: %d", port)
logging.info(f"Address: %s", address)

# Set up signal handling (ctrl-c)
signal.signal(signal.SIGINT, ctrl_c_pressed)

# Create the listening socket for the proxy
with socket(AF_INET, SOCK_STREAM) as skt:
    skt.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    skt.bind((address, port))
    skt.listen(MAX_QUEUED_CONNECTIONS)

    # Accept clients in a loop and process their requests
    while True:
        try:
            (client_skt, client_addr) = skt.accept()
            logging.info("New clinet connected: %s", client_addr)
            thrd = Thread(target=handle_client, args=[client_skt])
            thrd.start()

        except Exception as e:
            logging.error(f"Exception: {e}")
