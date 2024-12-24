from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Received GET request")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, GET!')

    def do_POST(self):
        print("Received POST request")
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        print(f"Data: {post_data}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, POST!')

    def do_PUT(self):
        print("Received PUT request")
        self.send_response(200)
        self.end_headers()

    def do_DELETE(self):
        print("Received DELETE request")
        self.send_response(200)
        self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8080), SimpleHTTPRequestHandler)
    print("Server running on http://localhost:8080")
    server.serve_forever()
