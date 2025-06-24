from socket import socket, AF_INET, SOCK_STREAM

with socket(AF_INET, SOCK_STREAM) as skt:
    skt.connect(("localhost", 2100))
    # skt.send(b"GET http://localhost:5500/proxy/cache/enable HTTP/1.0\r\n\r\n")
    skt.send(b"GET http://localhost:5500/info.txt HTTP/1.0\r\n\r\n")
    response = bytearray()
    resp_part = skt.recv(2048)
    while len(resp_part) != 0:
        response.extend(resp_part)
        resp_part = skt.recv(2048)

    print(response.decode())
