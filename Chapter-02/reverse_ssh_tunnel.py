import getpass
import socket
import select
import sys
import threading
from optparse import OptionParser

try:
    import paramiko
except ImportError:
    print("[!!] Missing required module: paramiko\nInstall it with: pip install paramiko")
    sys.exit(1)

SSH_PORT = 22
DEFAULT_PORT = 4000
g_verbose = True


def verbose(msg):
    if g_verbose:
        print(msg)


def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose(f"[!!] Forwarding request to {host}:{port} failed: {e}")
        chan.close()
        return

    verbose(f"[+] Tunnel open {chan.origin_addr} -> {chan.getpeername()} -> ({host}, {port})")

    while True:
        r, _, _ = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if not data:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if not data:
                break
            sock.send(data)

    chan.close()
    sock.close()
    verbose(f"[-] Tunnel closed from {chan.origin_addr}")


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    try:
        transport.request_port_forward("", server_port)
        verbose(f"[+] Listening for incoming SSH connections on port {server_port}...")
    except Exception as e:
        print(f"[!!] Failed to request port forward: {e}")
        return

    while True:
        try:
            chan = transport.accept(timeout=1000)
            if chan is None:
                continue
            thr = threading.Thread(target=handler, args=(chan, remote_host, remote_port))
            thr.daemon = True  # Updated per Python best practices
            thr.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            verbose(f"[!!] Tunnel accept error: {e}")


HELP = """\
Establish a reverse SSH tunnel from the SSH server back to your machine.
Similar to `ssh -R [remote_port]:[remote_host]:[remote_port] user@sshserver`.
"""


def get_host_port(spec, default_port):
    parts = (spec.split(":", 1) + [default_port])[:2]
    return parts[0], int(parts[1])


def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True,
                      help="Suppress informational output")
    parser.add_option("-p", "--remote-port", type="int", dest="port", default=DEFAULT_PORT,
                      help=f"Port on SSH server to forward (default: {DEFAULT_PORT})")
    parser.add_option("-u", "--user", type="string", dest="user", default=getpass.getuser(),
                      help=f"SSH username (default: {getpass.getuser()})")
    parser.add_option("-K", "--key", type="string", dest="keyfile", default=None,
                      help="Private key file for SSH authentication")
    parser.add_option("--no-key", action="store_false", dest="look_for_keys", default=True,
                      help="Do not look for or use a private key file")
    parser.add_option("-P", "--password", action="store_true", dest="readpass", default=False,
                      help="Prompt for SSH password input")
    parser.add_option("-r", "--remote", type="string", dest="remote", default=None, metavar="host:port",
                      help="Remote internal host and port to forward to (e.g. 127.0.0.1:80)")

    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error("Specify SSH server (e.g. user@host or host:port)")
    if options.remote is None:
        parser.error("You must specify a remote target host and port using -r")

    g_verbose = options.verbose
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)

    return options, (server_host, server_port), (remote_host, remote_port)


def main():
    options, server, remote = parse_options()

    password = None
    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose(f"[*] Connecting to SSH host {server[0]}:{server[1]} as {options.user}")
    try:
        client.connect(
            server[0],
            server[1],
            username=options.user,
            key_filename=options.keyfile,
            look_for_keys=options.look_for_keys,
            password=password,
        )
    except Exception as e:
        print(f"[!!] Failed to connect to {server[0]}:{server[1]}: {e}")
        sys.exit(1)

    verbose(f"[+] Forwarding remote port {options.port} to {remote[0]}:{remote[1]}")
    try:
        reverse_forward_tunnel(options.port, remote[0], remote[1], client.get_transport())
    except KeyboardInterrupt:
        print("[*] Caught Ctrl-C, exiting...")
        sys.exit(0)


if __name__ == "__main__":
    main()
