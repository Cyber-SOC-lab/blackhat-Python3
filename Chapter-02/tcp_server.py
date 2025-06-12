import socket
import threading

def get_server_config():
    bind_ip = input("Enter IP to bind to (default: 0.0.0.0): ").strip() or "0.0.0.0"
    try:
        bind_port = int(input("Enter port to bind to (default: 9999): ").strip() or 9999)
        if not (0 < bind_port < 65536):
            raise ValueError
    except ValueError:
        print("[!] Invalid port. Must be between 1 and 65535.")
        exit(1)
    return bind_ip, bind_port

def handle_client(client_socket, addr):
    try:
        print(f"[*] Handling connection from {addr[0]}:{addr[1]}")
        request = client_socket.recv(1024)
        if request:
            print(f"[>] Received from {addr[0]}:{addr[1]} -> {request.decode(errors='replace')}")
            client_socket.send(b"ACK!")
        else:
            print(f"[!] Empty request from {addr[0]}:{addr[1]}")
    except Exception as e:
        print(f"[!] Error handling client {addr[0]}:{addr[1]}: {e}")
    finally:
        client_socket.close()
        print(f"[*] Connection closed for {addr[0]}:{addr[1]}")

def start_server():
    bind_ip, bind_port = get_server_config()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((bind_ip, bind_port))
        server.listen(5)
        print(f"[*] Listening on {bind_ip}:{bind_port} (press Ctrl+C to stop)")

        while True:
            client, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=handle_client, args=(client, addr))
            client_handler.start()

    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
    except Exception as e:
        print(f"[!] Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
