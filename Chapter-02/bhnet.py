import sys
import socket
import threading
import subprocess
import argparse
import os


def run_command(command):
    command = command.strip()
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except Exception as e:
        output = f"Failed to execute command.\r\n{e}".encode()
    return output


def client_sender(buffer, target, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((target, port))
        if buffer:
            client.send(buffer.encode())

        while True:
            response = b""
            while True:
                data = client.recv(4096)
                response += data
                if len(data) < 4096:
                    break
            print(response.decode(), end="")

            buffer = input("") + "\n"
            client.send(buffer.encode())

    except Exception as e:
        print(f"[*] Exception! Exiting. Reason: {e}")
        client.close()


def server_loop(args):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((args.target, args.port))
        server.listen(5)
        print(f"[+] Listening on {args.target}:{args.port} ...")
    except Exception as e:
        print(f"[-] Failed to bind server: {e}")
        sys.exit(1)

    while True:
        client_socket, addr = server.accept()
        print(f"[+] Connection from {addr}")
        client_thread = threading.Thread(
            target=client_handler,
            args=(client_socket, args.upload, args.upload_destination, args.execute, args.command)
        )
        client_thread.start()


def client_handler(client_socket, upload, upload_destination, execute, command):
    if upload and upload_destination:
        file_buffer = b""
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            file_buffer += data

        try:
            with open(upload_destination, "wb") as f:
                f.write(file_buffer)
            client_socket.send(f"Successfully saved file to {upload_destination}\n".encode())
        except Exception as e:
            client_socket.send(f"Failed to save file to {upload_destination}: {e}\n".encode())

    if execute:
        output = run_command(execute)
        client_socket.send(output)

    if command:
        while True:
            client_socket.send(b"<BHP:#> ")
            cmd_buffer = b""
            while b"\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)
            response = run_command(cmd_buffer.decode())
            client_socket.send(response)


def main():
    parser = argparse.ArgumentParser(description="BHP Net Tool")
    parser.add_argument("-t", "--target", default="0.0.0.0", help="Target IP")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    parser.add_argument("-l", "--listen", action="store_true", help="Listen mode")
    parser.add_argument("-e", "--execute", help="Execute command on connect")
    parser.add_argument("-c", "--command", action="store_true", help="Command shell")
    parser.add_argument("-u", "--upload", action="store_true", help="Enable upload")
    parser.add_argument("--upload-destination", help="Destination path for uploaded file")

    args = parser.parse_args()

    if args.listen:
        server_loop(args)
    else:
        buffer = ""
        if not sys.stdin.isatty():
            buffer = sys.stdin.read()
        client_sender(buffer, args.target, args.port)


if __name__ == "__main__":
    main()


