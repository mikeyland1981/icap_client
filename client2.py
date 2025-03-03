#!/usr/bin/env python3
import socket
import ssl
import sys
import os
import argparse
import time
import select
from typing import Optional, Tuple, Dict, Any
import binascii


class IcapClient:
    """
    Client for communicating with ICAP servers over SSL/TLS to scan files.
    """
    def __init__(self, server: str, port: int = 1344, user_agent: str = "SCSOPS ICAP Client/1.1", debug: bool = False):
        """
        Initialize ICAP client with server details.
        
        Args:
            server: ICAP server hostname or IP
            port: ICAP server port (default: 1344)
            user_agent: User agent string to identify client
            debug: Enable verbose debug output
        """
        self.server = server
        self.port = port
        self.user_agent = user_agent
        self.debug = debug
        
    def log(self, message: str, level: str = "INFO") -> None:
        """Log a message if debugging is enabled."""
        if self.debug or level == "ERROR":
            print(f"[{level}] {message}")
        
    def scan_file(self, filename: str, service_path: str = "virus_scan", 
                  timeout: int = 300, read_timeout: int = 60) -> Dict[str, Any]:
        """
        Send a file to the ICAP server for scanning.
        
        Args:
            filename: Path to the file to be scanned
            service_path: ICAP service path
            timeout: Connection timeout in seconds
            read_timeout: Timeout for reading response chunks
            
        Returns:
            Dictionary containing response details and status
        """
        result = {
            "success": False,
            "raw_response": None,
            "status_code": None,
            "status_text": None,
            "headers": {},
            "error": None,
            "scan_result": "UNKNOWN"
        }
        
        # Create socket and wrap with SSL
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # WARNING: In production, use proper certificate verification
        
        conn = None
        try:
            conn = context.wrap_socket(sock=s)
            self.log(f"Connecting to {self.server}:{self.port}...")
            conn.settimeout(timeout)
            conn.connect((self.server, self.port))
            self.log("Connected successfully")
            
            # Send OPTIONS request first to check server capabilities
            if self._send_options_request(conn):
                self.log("Server responded to OPTIONS request, proceeding with file scan")
            else:
                self.log("Server did not respond to OPTIONS request, proceeding anyway", "WARNING")
            
            response_data = self._send_scan_request(conn, filename, service_path, read_timeout)
            
            if response_data:
                result["raw_response"] = response_data
                parsed = self._parse_icap_response(response_data)
                
                # Update result with parsed information
                result.update(parsed)
                result["success"] = True
            else:
                result["error"] = "No response received from server"
                
        except socket.timeout:
            result["error"] = f"Connection timed out when connecting to {self.server}:{self.port}"
            self.log(result["error"], "ERROR")
        except ConnectionRefusedError:
            result["error"] = f"Connection refused by {self.server}:{self.port}"
            self.log(result["error"], "ERROR")
        except Exception as e:
            result["error"] = f"Error: {str(e)}"
            self.log(result["error"], "ERROR")
            if self.debug:
                import traceback
                traceback.print_exc()
        finally:
            if conn:
                conn.close()
                
        return result
            
    def _send_options_request(self, conn: ssl.SSLSocket) -> bool:
        """
        Send an OPTIONS request to the ICAP server to check if it's responsive.
        
        Args:
            conn: Active SSL socket connection
            
        Returns:
            True if server responded properly, False otherwise
        """
        try:
            options_request = (
                f"OPTIONS icap://{self.server}/virus_scan ICAP/1.0\r\n"
                f"Host: {self.server}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"\r\n"
            )
            
            conn.settimeout(10)  # Short timeout for OPTIONS
            conn.sendall(options_request.encode('utf-8'))
            
            # Just try to get some response
            response = conn.recv(1024)
            return b"ICAP/1.0" in response
        except Exception as e:
            self.log(f"OPTIONS request failed: {str(e)}", "WARNING")
            return False
            
    def _send_scan_request(self, conn: ssl.SSLSocket, filename: str, 
                           service_path: str, read_timeout: int) -> Optional[bytes]:
        """
        Build and send the ICAP file scan request, then read the response.
        
        Args:
            conn: Active SSL socket connection
            filename: Path to file to send
            service_path: ICAP service path
            read_timeout: Timeout for reading response
            
        Returns:
            Raw response bytes or None if error occurred
        """
        # Read file content
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        file_size = len(file_data)
        self.log(f"File size: {file_size} bytes")
        
        # Try several ways of formatting the request to handle different server implementations
        try:
            # Standard format with Content-Length method
            payload = self._create_standard_payload(filename, file_data, service_path)
            
            # Send the request
            self.log("Sending file scan request...")
            conn.settimeout(30)  # Timeout for sending data
            conn.sendall(payload)
            self.log("Request sent, waiting for response...")
            
            # Improved response reading
            response_data = self._read_response_with_timeout(conn, read_timeout)
            
            # If we got no valid response, try alternative format
            if not response_data or len(response_data) < 10:
                self.log("No valid response received, trying alternative request format...", "WARNING")
                # Try chunked encoding approach
                payload = self._create_chunked_payload(filename, file_data, service_path)
                conn.sendall(payload)
                response_data = self._read_response_with_timeout(conn, read_timeout)
            
            return response_data
            
        except Exception as e:
            self.log(f"Error sending scan request: {str(e)}", "ERROR")
            if self.debug:
                import traceback
                traceback.print_exc()
            return None
    
    def _create_standard_payload(self, filename: str, file_data: bytes, service_path: str) -> bytes:
        """Create standard ICAP request payload with Content-Length."""
        # Base filename without path
        base_filename = os.path.basename(filename)
        
        # Construct HTTP headers for the encapsulated request
        http_headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.server}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Disposition: attachment; filename=\"{base_filename}\"\r\n"
            f"Content-Length: {len(file_data)}\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        # Construct ICAP headers
        icap_headers = (
            f"REQMOD icap://{self.server}/{service_path} ICAP/1.0\r\n"
            f"Host: {self.server}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Allow: 204\r\n"
            f"Encapsulated: req-hdr=0, req-body={len(http_headers)}\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        # Combine everything into the full payload
        payload = icap_headers + http_headers + file_data
        
        if self.debug:
            self.log(f"Request headers:\n{icap_headers.decode('utf-8', errors='replace')}")
            
        return payload
        
    def _create_chunked_payload(self, filename: str, file_data: bytes, service_path: str) -> bytes:
        """Create alternative ICAP request payload with chunked encoding."""
        # Base filename without path
        base_filename = os.path.basename(filename)
        
        # Construct HTTP headers for the encapsulated request
        http_headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.server}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Disposition: attachment; filename=\"{base_filename}\"\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        # Construct ICAP headers
        icap_headers = (
            f"REQMOD icap://{self.server}/{service_path} ICAP/1.0\r\n"
            f"Host: {self.server}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Allow: 204\r\n"
            f"Encapsulated: req-hdr=0, req-body={len(http_headers)}\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        # Format file data as chunked encoding
        chunk_size = 8192  # 8KB chunks
        chunked_data = b""
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i+chunk_size]
            chunk_header = f"{len(chunk):x}\r\n".encode('utf-8')
            chunked_data += chunk_header + chunk + b"\r\n"
        
        # Add final zero-length chunk to end the body
        chunked_data += b"0\r\n\r\n"
        
        # Combine everything into the full payload
        payload = icap_headers + http_headers + chunked_data
        
        if self.debug:
            self.log(f"Chunked request headers:\n{icap_headers.decode('utf-8', errors='replace')}")
            
        return payload

    def _read_response_with_timeout(self, conn: ssl.SSLSocket, timeout: int) -> Optional[bytes]:
        """
        Read the ICAP response with timeout.
        
        Args:
            conn: Active SSL socket connection
            timeout: Total timeout for reading the response
            
        Returns:
            Raw response bytes or None if error occurred
        """
        conn.setblocking(0)  # Set to non-blocking mode
        
        response_data = b""
        start_time = time.time()
        end_time = start_time + timeout
        
        # If we don't get any data in the first 5 seconds, try again with a poke
        first_data_received = False
        
        while time.time() < end_time:
            # Check if data is available to read
            try:
                readable, _, _ = select.select([conn], [], [], 1.0)
                
                if not readable:
                    # No data available yet
                    elapsed = time.time() - start_time
                    
                    # If we've waited 5 seconds with no data, send a small poke
                    if not first_data_received and elapsed > 5 and elapsed < 6:
                        self.log("No initial response, sending a 'poke' request...", "WARNING")
                        try:
                            conn.sendall(b"\r\n")  # Send empty line as a poke
                        except:
                            pass  # Ignore if this fails
                    
                    continue
                
                # Data is available, read it
                chunk = conn.recv(8192)
                
                if not chunk:
                    # Connection closed by server
                    self.log("Server closed connection")
                    break
                
                # We got some data
                first_data_received = True
                response_data += chunk
                
                # Show some of the response in debug mode
                if self.debug and len(response_data) <= 1024:
                    self.log(f"Response so far ({len(response_data)} bytes):\n" +
                             response_data.decode('utf-8', errors='replace')[:200] + "...")
                
                # Look for end markers
                if self._is_response_complete(response_data):
                    self.log(f"Response complete ({len(response_data)} bytes)")
                    break
                    
            except ssl.SSLWantReadError:
                # This is normal in non-blocking mode, just retry
                continue
            except socket.error as e:
                self.log(f"Socket error while reading: {e}", "ERROR")
                break
        
        # Check if we hit the timeout
        if time.time() >= end_time and not self._is_response_complete(response_data):
            self.log(f"Read timeout after receiving {len(response_data)} bytes", "WARNING")
            
            # If we got some data, try to make sense of it anyway
            if len(response_data) == 0:
                self.log("No data received from server", "ERROR")
                return None
        
        return response_data
        
    def _is_response_complete(self, data: bytes) -> bool:
        """
        Check if the response appears to be complete.
        
        Args:
            data: Current accumulated response data
            
        Returns:
            True if response appears complete, False otherwise
        """
        # For standard HTTP/ICAP responses with Content-Length
        if b"Content-Length:" in data and b"\r\n\r\n" in data:
            headers, body = data.split(b"\r\n\r\n", 1)
            headers_str = headers.decode('utf-8', errors='replace')
            
            for line in headers_str.split('\r\n'):
                if line.lower().startswith("content-length:"):
                    try:
                        length = int(line.split(":", 1)[1].strip())
                        return len(body) >= length
                    except ValueError:
                        pass
        
        # For chunked responses
        if b"Transfer-Encoding: chunked" in data:
            return b"\r\n0\r\n\r\n" in data
            
        # For ICAP responses with no encapsulated content
        if b"ICAP/1.0" in data and b"\r\n\r\n" in data:
            # Simple response with just headers
            return True
            
        # If response is fairly large, assume it's complete
        if len(data) > 1024:
            return True
            
        return False

    def _parse_icap_response(self, data: bytes) -> Dict[str, Any]:
        """
        Parse the ICAP response into structured format.
        
        Args:
            data: Raw response data
            
        Returns:
            Dictionary with parsed response details
        """
        result = {
            "status_code": None,
            "status_text": None,
            "headers": {},
            "scan_result": "UNKNOWN"
        }
        
        try:
            # Try to decode as text
            text = data.decode('utf-8', errors='replace')
            
            # Check if it's a valid ICAP response
            lines = text.split('\r\n')
            if not lines:
                return result
                
            # Parse status line
            status_line = lines[0]
            if status_line.startswith('ICAP/1.0'):
                parts = status_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        result["status_code"] = int(parts[1])
                        result["status_text"] = parts[2] if len(parts) > 2 else ""
                    except ValueError:
                        pass
            
            # If not valid ICAP, try HTTP fallback
            elif status_line.startswith('HTTP/1.'):
                parts = status_line.split(' ', 2)
                if len(parts) >= 2:
                    try:
                        result["status_code"] = int(parts[1])
                        result["status_text"] = parts[2] if len(parts) > 2 else ""
                    except ValueError:
                        pass
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if not line or line.isspace():
                    break
                    
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            result["headers"] = headers
            
            # Try to determine scan result
            self._interpret_scan_result(result, text)
            
        except Exception as e:
            self.log(f"Error parsing response: {str(e)}", "ERROR")
            if self.debug:
                # If text parsing failed, show hex dump
                self.log("First 200 bytes of raw response:")
                self.log(binascii.hexlify(data[:200]).decode('ascii'))
                
        return result
    
    def _interpret_scan_result(self, result: Dict[str, Any], text: str) -> None:
        """
        Try to interpret virus scan result from response.
        
        Args:
            result: Result dictionary to update
            text: Response text
        """
        # Common virus scan result headers
        virus_headers = [
            "X-Infection-Found", "X-Virus-ID", "X-Response-Info", 
            "X-Virus-Name", "X-Virus-Found"
        ]
        
        # Check headers
        for header, value in result["headers"].items():
            header_lower = header.lower()
            for virus_header in virus_headers:
                if virus_header.lower() in header_lower:
                    if "true" in value.lower() or "yes" in value.lower() or "found" in value.lower():
                        result["scan_result"] = "INFECTED"
                    elif "false" in value.lower() or "no" in value.lower() or "not found" in value.lower():
                        result["scan_result"] = "CLEAN"
                    else:
                        # If ambiguous but header exists, assume infected
                        result["scan_result"] = "INFECTED"
        
        # Check status code
        if result["status_code"]:
            if result["status_code"] == 204:
                result["scan_result"] = "CLEAN"  # No modifications needed
            elif result["status_code"] == 200:
                # Could be either clean or infected depending on headers
                if result["scan_result"] == "UNKNOWN":
                    # Look for common patterns
                    text_lower = text.lower()
                    if "virus" in text_lower or "malware" in text_lower or "infected" in text_lower:
                        result["scan_result"] = "INFECTED"
                    elif "clean" in text_lower or "no virus" in text_lower or "no infection" in text_lower:
                        result["scan_result"] = "CLEAN"


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='ICAP Client for file scanning')
    parser.add_argument('server', help='ICAP server hostname or IP')
    parser.add_argument('filename', help='File to scan')
    parser.add_argument('--port', type=int, default=1344, help='ICAP server port (default: 1344)')
    parser.add_argument('--conn-timeout', type=int, default=300, 
                        help='Connection timeout in seconds (default: 300)')
    parser.add_argument('--read-timeout', type=int, default=120,
                        help='Read timeout in seconds (default: 120)')
    parser.add_argument('--service', default='virus_scan',
                        help='ICAP service path (default: virus_scan)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable verbose debug output')
    return parser.parse_args()


def main():
    """Main entry point for the ICAP client."""
    args = parse_arguments()
    
    # Validate file exists
    if not os.path.exists(args.filename):
        print(f"Error: File '{args.filename}' does not exist.")
        sys.exit(1)
    
    # Create client and scan file
    client = IcapClient(args.server, args.port, debug=args.debug)
    result = client.scan_file(
        args.filename, 
        service_path=args.service,
        timeout=args.conn_timeout,
        read_timeout=args.read_timeout
    )
    
    # Print results
    print("\n---- ICAP Scan Results ----")
    
    if result["success"]:
        print(f"Status: {result['status_code']} {result['status_text']}")
        print(f"Scan Result: {result['scan_result']}")
        
        # Print important headers
        print("\nImportant Headers:")
        important_headers = ["X-Infection-Found", "X-Virus-ID", "X-Virus-Name", 
                            "X-Response-Info", "X-Virus-Found"]
        header_found = False
        
        for header, value in result["headers"].items():
            for important in important_headers:
                if important.lower() in header.lower():
                    print(f"{header}: {value}")
                    header_found = True
        
        if not header_found:
            print("No virus-specific headers found")
        
        # Print full response in debug mode
        if args.debug and result["raw_response"]:
            print("\n---- Full Server Response ----")
            print(result["raw_response"].decode('utf-8', errors='replace'))
    else:
        print(f"Scan Failed: {result['error']}")
        sys.exit(1)


if __name__ == "__main__":
    main()