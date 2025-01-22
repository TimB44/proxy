# Place your imports here
import signal
from optparse import OptionParser
import sys
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from enum import Enum
from typing import Tuple, Optional, Dict
import re
import logging
import threading

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
BAD_REQUEST_RESPOSE = b"HTTP/1.0 400 Bad Request\r\n"
NOT_IMPL_RESPOSE = b"HTTP/1.0 501 Not Implemented\r\n"


# Signal handler for pressing ctrl-c
def ctrl_c_pressed(signal, frame):
    sys.exit(0)


# Defines the differnt possible error cases when parsing an HTTP request
class ParseError(Enum):
    NOTIMPL = 1
    BADREQ = 2


# Parses the given bytes as a http request.
# Return an error or a tupele of (Host, Port, Path, Headers)
def parse_request(
    message: bytes,
) -> ParseError | Tuple[str, int, str, Dict[str, str]]:
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

    headers: Dict[str, str] = {}
    assert match.start() == 0

    rest = message[match.end() :]
    logging.debug(f"Parsing headers:\n{len(rest)}")

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


# Creates an HTTP reqest in a bytes object using the given info
def generate_http_request(
    host: str, port: int, path: str, headers: Dict[str, str]
) -> bytes:
    req = bytearray()
    req.extend(f"GET {path} HTTP/1.0\r\n".encode())
    req.extend(f"Host: {host}:{port}\r\n".encode())
    req.extend(f"Connection: close\r\n".encode())
    for key, value in headers.items():
        if key == "Connection":
            continue
        req.extend(f"{key}: {value}\r\n".encode())

    req.extend("\r\n".encode())

    return bytes(req)


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

        # Send the proper respose if there is an error
        if isinstance(parsed, ParseError):
            if parsed == ParseError.NOTIMPL:
                logging.debug("Error: Not Implemented")
                client_skt.sendall(NOT_IMPL_RESPOSE)
            elif parsed == ParseError.BADREQ:
                logging.debug("Error: Bad Request")
                client_skt.sendall(BAD_REQUEST_RESPOSE)
            return

        (host, port, path, headers) = parsed

        # Create the socket for the server
        with socket(AF_INET, SOCK_STREAM) as server_skt:
            server_skt.connect((host, port))
            http_message = generate_http_request(host, port, path, headers)
            logging.debug(f"Sending message to server:\n{http_message}")
            server_skt.sendall(http_message)
            logging.debug(f"Sent message")

            resp = server_skt.recv(BUF_SIZE)
            while len(resp) != 0:
                logging.debug(f"Sending response to client:\n{resp}")
                client_skt.sendall(resp)
                resp = server_skt.recv(BUF_SIZE)

            logging.debug(f"Done sending request")

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
            thrd = threading.Thread(target=handle_client, args=[client_skt])
            thrd.start()

        except Exception as e:
            logging.error(f"Exception: {e}")
