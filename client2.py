#!/usr/bin/env python3
import socket
import ssl
import sys
import os
import argparse
import time
from typing import Optional, Tuple


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
        
    def scan_file(self, filename: str, timeout: int = 300, read_timeout: int = 30) -> Optional[str]:
        """
        Send a file to the ICAP server for scanning.
        
        Args:
            filename: Path to the file to be scanned
            timeout: Connection timeout in seconds
            read_timeout: Timeout for reading response chunks
            
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
            
            response = self._handle_request(conn, filename, read_timeout)
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
        
    def _handle_request(self, conn: ssl.SSLSocket, filename: str, read_timeout: int) -> str:
        """
        Build and send the ICAP request, then process the response.
        
        Args:
            conn: Active SSL socket connection
            filename: Path to file to send
            read_timeout: Timeout for reading response chunks
            
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
        
        # Improved response reading with progressive timeouts
        return self._read_response(conn, read_timeout)
    
    def _read_response(self, conn: ssl.SSLSocket, read_timeout: int) -> str:
        """
        Read the ICAP response with proper handling of chunked encoding.
        
        Args:
            conn: Active SSL socket connection
            read_timeout: Timeout for reading response chunks
            
        Returns:
            Server response as string
        """
        # Set socket to non-blocking mode to avoid hanging
        conn.setblocking(False)
        
        response_data = b""
        headers_complete = False
        chunked_encoding = False
        content_length = None
        body_start = 0
        start_time = time.time()
        
        while True:
            # Check if we've been waiting too long
            if time.time() - start_time > read_timeout:
                print("Warning: Overall read timeout reached")
                break
                
            # Try to read data with a short timeout
            try:
                ready_to_read = self._socket_wait_readable(conn, timeout=1.0)
                if not ready_to_read:
                    # No data available yet, but we haven't timed out completely
                    continue
                
                chunk = conn.recv(8192)
                if not chunk:
                    # Connection closed by server
                    break
                    
                response_data += chunk
                
                # Reset the start time since we're actively receiving data
                start_time = time.time()
                
                # Process headers if we haven't done so yet
                if not headers_complete:
                    if b"\r\n\r\n" in response_data:
                        headers_complete = True
                        headers, body = response_data.split(b"\r\n\r\n", 1)
                        headers_str = headers.decode('utf-8', errors='replace')
                        
                        # Check for chunked encoding
                        if "Transfer-Encoding: chunked" in headers_str:
                            chunked_encoding = True
                        
                        # Check for Content-Length
                        for line in headers_str.split('\r\n'):
                            if line.lower().startswith("content-length:"):
                                try:
                                    content_length = int(line.split(":", 1)[1].strip())
                                except ValueError:
                                    pass
                        
                        body_start = len(response_data) - len(body)
                
                # For non-chunked responses with Content-Length
                if headers_complete and content_length is not None:
                    if len(response_data) - body_start >= content_length:
                        print("Response complete (content-length reached)")
                        break
                
                # For chunked responses, check for the terminating chunk
                if chunked_encoding and b"\r\n0\r\n\r\n" in response_data:
                    print("Response complete (chunked encoding end marker found)")
                    break
                    
            except ssl.SSLWantReadError:
                # This is normal in non-blocking mode, just retry
                continue
            except socket.error as e:
                print(f"Socket error: {e}")
                break
        
        # Use the more lenient 'replace' error handler for decoding
        response = response_data.decode('utf-8', errors='replace')
        
        # Check if we have a valid ICAP response
        if not response.startswith("ICAP"):
            print("Warning: Response doesn't appear to be a valid ICAP response")
            
        return response
    
    def _socket_wait_readable(self, sock, timeout=1.0) -> bool:
        """
        Wait until socket is readable or timeout occurs.
        
        Args:
            sock: Socket to check
            timeout: How long to wait in seconds
            
        Returns:
            True if socket is readable, False on timeout
        """
        import select
        try:
            ready = select.select([sock], [], [], timeout)
            return bool(ready[0])
        except select.error:
            return False


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ICAP Client for file scanning')
    parser.add_argument('server', help='ICAP server hostname or IP')
    parser.add_argument('filename', help='File to scan')
    parser.add_argument('--port', type=int, default=1344, help='ICAP server port (default: 1344)')
    parser.add_argument('--conn-timeout', type=int, default=300, 
                        help='Connection timeout in seconds (default: 300)')
    parser.add_argument('--read-timeout', type=int, default=60,
                        help='Read timeout in seconds (default: 60)')
    parser.add_argument('--service', default='virus_scan',
                        help='ICAP service path (default: virus_scan)')
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
    response = client.scan_file(args.filename, args.conn_timeout, args.read_timeout)
    
    if response:
        print("\n---- ICAP Server Response ----")
        print(response)
        
        # Extract status line for quick reference
        status_line = response.split('\r\n')[0] if '\r\n' in response else response.split('\n')[0]
        print("\n---- Scan Result Summary ----")
        print(f"Status: {status_line}")
        
        # Look for common virus scan result headers
        result_headers = ["X-Infection-Found", "X-Virus-ID", "X-Response-Info", "X-Virus-Name"]
        result_found = False
        for line in response.split('\r\n'):
            for header in result_headers:
                if line.startswith(header):
                    print(line)
                    result_found = True
        
        if not result_found:
            print("No explicit virus information found in headers.")
            # Look for common result patterns in the response
            if "not found" in response.lower() or "no virus" in response.lower():
                print("Likely result: No threats detected")
            elif "infected" in response.lower() or "virus" in response.lower():
                print("Likely result: Threat detected")


if __name__ == "__main__":
    main()