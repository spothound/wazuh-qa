# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import socket
import struct
from os import path
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.utils import retry

request_socket = path.join(WAZUH_PATH, 'queue', 'sockets', 'request')
request_protocol = "tcp"


def send_request(msg_request, response_size=100):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    request_msg = struct.pack('<I', len(msg_request)) + msg_request.encode()

    @retry(socket.error)
    def connection(s, request):
        s.connect(request)

    @retry(socket.error)
    def send_msg(s, msg):
        s.send(msg)

    @retry(ValueError)
    def recv_response(s, size):
        answer = s.recv(size).decode()
        if answer == '':
            raise ValueError
        return answer

    connection(sock, request_socket)
    send_msg(sock, request_msg)
    response = recv_response(sock, response_size)

    sock.close()

    return response