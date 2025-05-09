import socket
import ssl
import os
import time
import argparse

class IcapClient:
    def __init__(self, url, port):
        self.url = url
        self.port = port
        self.user_agent = "SCSOPS ICAP Client/1.0"
        self.chunk_size = 524288

    def send_file(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            print("File size:", file_size)
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)  
        conn = context.wrap_socket(s, server_hostname=self.url)

        try:
            conn.settimeout(600)
            conn.connect((self.url, self.port))
            print("Connected to ICAP server...")

            start_time = time.time()
            # Correct Encapsulation
            req_body_position = len("POST /post HTTP/1.1\r\n\r\n")  

            # ICAP Request Headers
            icap_headers = f"""REQMOD icap://{self.url}/validation ICAP/1.0\r
Host: {self.url}\r
User-Agent: {self.user_agent}\r
Allow: 204\r
Encapsulated: req-hdr=0, req-body={req_body_position}\r
\r
POST /post HTTP/1.1\r
\r
""".encode("utf-8")

            conn.sendall(icap_headers)

            # Sending file in chunks
            with open(file_path, "rb") as file:
                while True:
                    chunk = file.read(self.chunk_size)
                    if not chunk:
                        break
                    hex_length = f"{len(chunk):X}\r\n".encode("utf-8")  # Hex chunk size
                    conn.sendall(hex_length + chunk + b"\r\n")

            # Send terminating zero chunk
            conn.sendall(b"0\r\n\r\n")

            response = self.receive_response(conn)

            end_time = time.time()

            scan_time = end_time - start_time

            print(f"Scan Time: {scan_time:.3f} seconds")

            return response

        except socket.timeout:
            print("Error: Connection timed out while waiting for ICAP server response.")
        except Exception as e:
            print(f"Error during ICAP request: {e}")
        finally:
            conn.close()

    def receive_response(self, conn):
        """Read the full response from the ICAP server"""
        data = b""
        while True:
            chunk = conn.recv(4096)  # Read in 4KB chunks
            if not chunk:
                break
            data += chunk

        response_text = data.decode("utf-8", "ignore")

        lines = response_text.split("\r\n")

        icap_response = []
        for line in lines:
            if line.startswith("ICAP/1.0") or line.startswith("ISTag:") or line.startswith("Encapsulated:") or line.startswith("X-") or line.startswith("HTTP/1.1") or ":" in line:
                icap_response.append(line)
            if line == "":
                break

        print("ICAP Response:")
        for line in icap_response:
            print(line)

        return response_text


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICAP Client")
    parser.add_argument("-u", "--url", help="ICAP server URL", required=True)
    parser.add_argument("-p", "--port", type=int, help="ICAP server port", default=1344)
    parser.add_argument("-f", "--file", help="File to be scanned", required=True)
    args = parser.parse_args()

    icap_client = IcapClient(args.url, args.port)
    response = icap_client.send_file(args.file)