"""
Root Agent Client — Synchronous Python client for the root agent daemon.

Usage:
    from root_agent_client import call_root_agent
    result = call_root_agent('qm-start', vmid=100)
    if result['ok']:
        print(result['output'])
"""

import json
import socket
import struct


SOCKET_PATH = '/run/blockhost/root-agent.sock'
DEFAULT_TIMEOUT = 300  # seconds


class RootAgentError(Exception):
    """Error from root agent."""
    pass


class RootAgentConnectionError(RootAgentError):
    """Cannot connect to root agent."""
    pass


def call_root_agent(action: str, timeout: float = DEFAULT_TIMEOUT, **params) -> dict:
    """Send a command to the root agent and return the response.

    Args:
        action: Action name (e.g. 'qm-start', 'iptables-open')
        timeout: Socket timeout in seconds
        **params: Action parameters

    Returns:
        Response dict with 'ok' key

    Raises:
        RootAgentConnectionError: Cannot connect to socket
        RootAgentError: Agent returned an error
    """
    msg = json.dumps({'action': action, 'params': params}).encode('utf-8')

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(SOCKET_PATH)
    except (OSError, ConnectionRefusedError) as e:
        raise RootAgentConnectionError(f'Cannot connect to root agent: {e}')

    try:
        # Send length-prefixed message
        sock.sendall(struct.pack('>I', len(msg)) + msg)

        # Read response length
        header = _recv_exact(sock, 4)
        length = struct.unpack('>I', header)[0]

        # Read response body
        data = _recv_exact(sock, length)
        response = json.loads(data.decode('utf-8'))

        if not response.get('ok'):
            raise RootAgentError(response.get('error', 'Unknown error'))

        return response

    finally:
        sock.close()


def _recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RootAgentConnectionError('Connection closed by root agent')
        buf += chunk
    return buf
