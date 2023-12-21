import socket

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPResponse, HTTPRequest

from constants import NO_PROTO


def check_dns_protocol(host, port, transport_protocol, timeout):
    request = bytes(DNS(rd=1, qd=DNSQR(qname="www.example.com")))

    return check_protocol(host, port, transport_protocol, timeout, request,
                          lambda response: DNS(response).qr == 1)


def check_echo_protocol(host, port, transport_protocol, timeout):
    request = b'ECHO'
    return check_protocol(host, port, transport_protocol, timeout, request,
                          lambda response: response == request)


def check_http_protocol(host, port, transport_protocol, timeout):
    request = bytes(HTTP() / HTTPRequest())

    return check_protocol(host, port, transport_protocol, timeout, request,
                          lambda response: HTTP(response).haslayer(
                              HTTPResponse))


def check_protocol(host, port, transport_protocol, timeout, request,
                   check_response):
    try:
        if transport_protocol.upper() == 'TCP':
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif transport_protocol.upper() == 'UDP':
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            raise ValueError(
                "Invalid transport protocol. Must be 'tcp' or 'udp'.")

        client_socket.settimeout(timeout)
        client_socket.connect((host, port))

        client_socket.sendall(request)
        response, _ = client_socket.recvfrom(1024)
        client_socket.close()
        return response is not None and check_response(response)

    except socket.error or socket.timeout:
        return False


APPLICATION_PROTOCOLS = {
    'TCP': {
        'HTTP': check_http_protocol,
        'DNS': check_dns_protocol,
        'ECHO': check_echo_protocol
    },
    'UDP': {
        'DNS': check_dns_protocol,
        'ECHO': check_echo_protocol
    }
}


def guess_application_protocol(host, port, transport_protocol, timeout):
    possible_protocols = APPLICATION_PROTOCOLS[transport_protocol.upper()]
    for name, checker in possible_protocols.items():
        if checker(host, port, transport_protocol, timeout):
            return name
    return NO_PROTO
