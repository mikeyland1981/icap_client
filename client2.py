#!/usr/bin/env python3
import socket
import ssl
import sys
import os
import argparse
from typing import Optional


class IcapClient:
    """
    Client for communicating with ICAP servers over SSL/TLS to scan files.
    """
    def __init__(self, server: str, port: int = 1344, user_agent: str = "SCSOPS ICAP Client/1.1"):
        """
        Initialize ICAP client with server details.
        
        Args:
            server: ICAP server hostname or IP
            port: ICAP server port (default: 1344)
            user_agent: User agent string to identify client
        """
        self.server = server
        self.port = port
        self.user_agent = user_agent
        
    def scan_file(self, filename: str, timeout: int = 300) -> Optional[str]:
        """
        Send a file to the ICAP server for scanning.
        
        Args:
            filename: Path to the file to be scanned
            timeout: Connection timeout in seconds
            
        Returns:
            Server response as string or None if error occurred
        """
        # Create socket and wrap with SSL
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # WARNING: In production, use proper certificate verification
        
        conn = context.wrap_socket(sock=s)
        
        try:
            print(f"Connecting to {self.server}:{self.port}...")
            conn.settimeout(timeout)
            conn.connect((self.server, self.port))
            print("Connected. Sending file...")
            
            response = self._handle_request(conn, filename)
            return response
            
        except socket.timeout:
            print("Error: Connection timed out")
        except ConnectionRefusedError:
            print(f"Error: Connection refused by {self.server}:{self.port}")
        except Exception as e:
            print(f"Error: {str(e)}")
        finally:
            conn.close()
            
        return None
        
    def _handle_request(self, conn: ssl.SSLSocket, filename: str) -> str:
        """
        Build and send the ICAP request, then process the response.
        
        Args:
            conn: Active SSL socket connection
            filename: Path to file to send
            
        Returns:
            Server response as string
        """
        # Read file content
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        file_size = len(file_data)
        print(f"File size: {file_size} bytes")
        
        # Construct HTTP headers for the encapsulated request
        http_headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.server}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {file_size}\r\n"
            f"\r\n"
        )
        
        # Construct ICAP headers
        icap_headers = (
            f"REQMOD icap://{self.server}/virus_scan ICAP/1.0\r\n"
            f"Host: {self.server}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Allow: 204\r\n"
            f"Encapsulated: req-hdr=0, req-body={len(http_headers)}\r\n"
            f"\r\n"
        )
        
        # Combine everything into the full payload
        payload = icap_headers.encode('utf-8') + http_headers.encode('utf-8') + file_data
        
        # Send the request
        conn.sendall(payload)
        print("Request sent, waiting for response...")
        
        # Read the response
        response_data = b""
        while True:
            try:
                chunk = conn.recv(8192)
                if not chunk:
                    break
                response_data += chunk
                
                # Check if we've reached the end of the response
                if b"\r\n0\r\n\r\n" in response_data:
                    break
            except socket.timeout:
                print("Warning: Read timeout, response may be incomplete")
                break
        
        response = response_data.decode('utf-8', errors='replace')
        return response


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ICAP Client for file scanning')
    parser.add_argument('server', help='ICAP server hostname or IP')
    parser.add_argument('filename', help='File to scan')
    parser.add_argument('--port', type=int, default=1344, help='ICAP server port (default: 1344)')
    parser.add_argument('--timeout', type=int, default=300, help='Connection timeout in seconds (default: 300)')
    return parser.parse_args()


def main():
    """Main entry point for the ICAP client."""
    args = parse_arguments()
    
    # Validate file exists
    if not os.path.exists(args.filename):
        print(f"Error: File '{args.filename}' does not exist.")
        sys.exit(1)
    
    # Create client and scan file
    client = IcapClient(args.server, args.port)
    response = client.scan_file(args.filename, args.timeout)
    
    if response:
        print("\n---- ICAP Server Response ----")
        print(response)
        
        # Extract status line for quick reference
        status_line = response.split('\r\n')[0] if '\r\n' in response else response.split('\n')[0]
        print("\n---- Scan Result Summary ----")
        print(f"Status: {status_line}")
        
        # Look for common virus scan result headers
        result_headers = ["X-Infection-Found", "X-Virus-ID", "X-Response-Info"]
        for line in response.split('\r\n'):
            for header in result_headers:
                if line.startswith(header):
                    print(line)


if __name__ == "__main__":
    main()