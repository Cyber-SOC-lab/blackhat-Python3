import sys
import socket
import threading

def server_loop(local_host, local_port, remote_host, remote_port, receive_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, local_port))
    except Exception as e:
        print(f"[!!] Failed to listen on {local_host}:{local_port}")
        print(f"[!!] Error: {e}")  # Print the actual error message
        sys.exit(1) #Exit with a non-zero code to indicate an error

    print(f"[*] Listening on {local_host}:{local_port}")

    server.listen(5)

    while True:
        try: # Add try-except block to handle potential client connection issues
            client_socket, addr = server.accept()
            print(f"[==>] Received incoming connection from {addr[0]}:{addr[1]}")

            proxy_thread = threading.Thread(target=proxy_handler,
                                            args=(client_socket, remote_host, remote_port, receive_first))
            proxy_thread.start()
        except KeyboardInterrupt:
            print("[*] Server shutting down...")
            server.close()
            sys.exit(0)
        except Exception as e:
            print(f"[!!] Error accepting connection: {e}")


def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        remote_socket.connect((remote_host, remote_port))
    except Exception as e:
        print(f"[!!] Could not connect to remote host: {e}")
        client_socket.close()
        return

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        if remote_buffer:
            hexdump(remote_buffer)
            remote_buffer = response_handler(remote_buffer) #Handle the response before sending it to the client
            client_socket.send(remote_buffer)

    while True:
        try:
            local_buffer = receive_from(client_socket)
            if local_buffer:
                print("[==>] Received %d bytes from localhost." % len(local_buffer))
                hexdump(local_buffer)
                local_buffer = request_handler(local_buffer)
                remote_socket.send(local_buffer)
                print("[==>] Sent to remote")

            remote_buffer = receive_from(remote_socket)
            if remote_buffer:
                print("[<==] Received %d bytes from remote." % len(remote_buffer))
                hexdump(remote_buffer)
                remote_buffer = response_handler(remote_buffer)
                client_socket.send(remote_buffer)
                print("[<==] Sent to localhost.")

            if not local_buffer and not remote_buffer:
                break

        except socket.error as e: # Catch socket errors to prevent crashes
            print(f"[!!] Socket error: {e}")
            break
        except Exception as e:
            print(f"[!!] An error occurred in proxy_handler: {e}")
            break

    client_socket.close()
    remote_socket.close()
    print("[*] Connection closed.")


def hexdump(src, length=16, sep=b'.'):
    result = []
    for i in range(0, len(src), length):
        subSrc = src[i:i + length]
        hexa = b''.join([b'%02X ' % x for x in subSrc])
        text = b''.join([x.to_bytes(1, 'big') if 0x20 <= x < 0x7F else sep for x in subSrc])
        result.append(b'%04X   %s   %s' % (i, hexa, text))
    print(b'\n'.join(result))



def receive_from(connection):
    buffer = b""  # Use bytes for buffer
    connection.settimeout(2)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except socket.timeout:
        pass
    except Exception as e:
        print(f"[!!] Receive error: {e}")
    return buffer

def request_handler(buffer):
    # Perform packet modifications here
    return buffer

def response_handler(buffer):
    # Perform packet modifications here
    return buffer

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: ./proxy.py 127.0.0.1 9000 10.0.0.1 80 True")
        sys.exit(1)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])         # 'int(sys.argv[4])'
    receive_first = sys.argv[5].lower() == "true" #More robust boolean conversion

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == "__main__":
    main()