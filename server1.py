# ----- IMPORTING ALL REQUIRMENTS -----
import http.server
import socketserver
import random
import string
import json
import sys
import signal
import os
import urllib.parse
import threading 
import psutil
from typing import Dict, Any, Optional, Callable, Iterable
import contextlib
import subprocess
from io import StringIO
from colorama import init, Fore, Style, Back
import re
from waitress import serve 
from wsgiref.headers import Headers

init(autoreset=True)

COLOR_SUCCESS = Fore.GREEN
COLOR_ERROR = Fore.RED + Style.BRIGHT
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.CYAN
COLOR_DEBUG = Fore.MAGENTA
COLOR_RESET = Style.RESET_ALL


# ----- TYPE DEFINITIONS -----
ServerInfo = Dict[str, Any] # {"token": str, "pid": int}
ServerIndex = Dict[str, ServerInfo] # {"port_str": ServerInfo}

# ----- GLOBAL STATE for Server Manager and Running Server -----
server_manager: 'Server' = None
# The running_server_httpd is no longer TCPServer but the WSGI server instance
running_server_wsgi: Optional[Any] = None 


# ----- ERRORS -----
class ServerErrors(Exception):
    """Base class for custom server manager exceptions."""
    def __init__(self, message):
        super().__init__(message)

class ServerExists(ServerErrors): pass
class ServerDataBaseError(ServerErrors): pass
class ServerPOSTError(ServerErrors): pass
class ServerKillError(ServerErrors): pass
class ServerNotFound(ServerErrors): pass
class ServerAccessDenied(ServerErrors): pass
class ServerManagerActionError(ServerErrors): pass 


# ----- HELPER FUNCTIONS -----

@contextlib.contextmanager
def captured_output():
    """Context manager to capture stdout and stderr."""
    new_stdout, new_stderr = StringIO(), StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_stdout, new_stderr
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr


# Helper function to remove ALL Colorama/ANSI escape codes
def _strip_color_codes(message: str) -> str:
    # This regex is designed to catch standard ANSI escape sequences
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', message)


# WSGI Helper: Format a response for the Waitress manager
def _format_wsgi_response(message: str, code: int = 200, code_style: bool = False, is_error: bool = False) -> str:
    """Formats the HTML response body for the WSGI application."""
    cleaned_message = _strip_color_codes(message)
    
    if code_style:
        # Use pre for code style output (like the server list)
        return f"<pre style='background-color: #2e4747; color: white; border: none; padding: 0;'>{cleaned_message}</pre>"
    elif is_error:
        # HTML color for the web error response
        return f"<h1 style='color: #ff6363;'>ERROR {code}: {cleaned_message}</h1>"
    else:
        # Simple H1 for status messages
        return f"<h1 style='color: #5cb85c;'>{cleaned_message}</h1>"


# --- NEW: WSGI Application for the Manager Dashboard ---
def manager_wsgi_app(environ: Dict[str, Any], start_response: Callable) -> Iterable[bytes]:
    """The main WSGI application for the server manager dashboard."""
    global server_manager
    
    path = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    
    response_body = b''
    status = '200 OK'
    headers = [('Content-type', 'text/html')]

    if method == 'GET':
        # --- Handle Static File Serving (index.html, manager_script.js) ---
        if path == '/' or path == '/index.html':
            try:
                with open('index.html', 'rb') as f:
                    response_body = f.read()
                    headers = [('Content-type', 'text/html')]
            except FileNotFoundError:
                status = '404 Not Found'
                response_body = b"<h1>404: Dashboard File Not Found</h1>"
        elif path == '/manager_script.js':
            try:
                with open('manager_script.js', 'rb') as f:
                    response_body = f.read()
                    headers = [('Content-type', 'application/javascript')]
            except FileNotFoundError:
                status = '404 Not Found'
                response_body = b"<h1>404: Script File Not Found</h1>"
        else:
            status = '404 Not Found'
            response_body = b"<h1>404: Not Found</h1>"

    elif method == 'POST':
        try:
            content_length = int(environ.get('CONTENT_LENGTH', 0))
            post_data_bytes = environ['wsgi.input'].read(content_length)
            post_data = post_data_bytes.decode('utf-8')
            parsed_data = urllib.parse.parse_qs(post_data)

        except Exception as e:
            status = '500 Internal Server Error'
            response_html = _format_wsgi_response(f"Failed to read POST data: {e}", 500, is_error=True)
            response_body = response_html.encode('utf-8')
            start_response(status, headers)
            return [response_body]


        # --- Internal Server Kill (/submit) - Used by a running server's local dashboard ---
        if path == '/submit':
            token = parsed_data.get('token', [''])[0].strip()
            command = parsed_data.get('command', [''])[0].strip().lower()

            if command == 'kill':
                # The manager dashboard doesn't have the context to shut down its own server process
                # via this internal API. This endpoint is typically hit by the server itself.
                # Since the manager runs in one process and the children in others, 
                # this logic is slightly complicated in a single script.
                # For this Waitress-based manager, we'll implement the kill via the manager action.
                # This /submit endpoint is mainly for the *target* server to kill itself.
                # The Manager's index.html POSTs to its own /submit, which is handled here.
                # Waitress doesn't support the 'shutdown' thread trick, so we rely on the
                # kill via the '/manager-action' endpoint which uses psutil.
                response_html = _format_wsgi_response("INFO: Use /manager-action with 'kill' and the token for reliable kill.", code_style=False)
            else:
                status = '400 Bad Request'
                response_html = _format_wsgi_response("Unknown command.", 400, is_error=True)


        # --- Manager Actions (/manager-action) ---
        elif path == '/manager-action':
            try:
                action = parsed_data.get('action', [''])[0].strip().lower()
                identifier = parsed_data.get('identifier', [''])[0].strip()

                if action == 'start':
                    if not identifier or ':' not in identifier:
                        raise ServerManagerActionError("Invalid identifier format for start. Must be 'port:id'.")
                    
                    # --- EXECUTE START COMMAND ---
                    port_str, id_str = identifier.split(':')
                    command_script = os.path.abspath(sys.argv[0]) # Use the current script path
                    
                    # Execute the start command in a new background process
                    # NOTE: We use the current script to run the 'start' command line logic
                    command = [sys.executable, command_script, 'start', port_str, id_str]
                    
                    # Detach the subprocess
                    subprocess.Popen(command, close_fds=True, start_new_session=True)

                    response_html = _format_wsgi_response(f"SUCCESS: Server start command dispatched for port {port_str}. Check terminal for PID and token.", code_style=True)
                
                elif action == 'kill':
                    if not identifier:
                        raise ServerManagerActionError("Kill Error: Port or Token identifier is required.")

                    with captured_output() as (out, err):
                        server_manager.kill_server(identifier)
                    
                    output_message = out.getvalue().strip()
                    response_html = _format_wsgi_response(output_message, code_style=True)
                    
                elif action == 'list':
                    with captured_output() as (out, err):
                        server_manager.list_servers()
                    
                    output_message = out.getvalue().strip()
                    response_html = _format_wsgi_response(output_message, code_style=True)
                    
                else:
                    status = '400 Bad Request'
                    response_html = _format_wsgi_response(f"Unknown manager action: {action}", 400, is_error=True)
                        
            except ServerNotFound as e:
                status = '404 Not Found'
                response_html = _format_wsgi_response(str(e), 404, is_error=True)
            except ServerKillError as e:
                status = '500 Internal Server Error'
                response_html = _format_wsgi_response(str(e), 500, is_error=True)
            except ServerManagerActionError as e:
                status = '400 Bad Request'
                response_html = _format_wsgi_response(str(e), 400, is_error=True)
            except Exception as e:
                status = '500 Internal Server Error'
                print(f"{COLOR_ERROR}Unexpected Manager Action Error: {e}{COLOR_RESET}")
                response_html = _format_wsgi_response(f"An unexpected server error occurred: {e}", 500, is_error=True)
        
        else:
            status = '404 Not Found'
            response_html = _format_wsgi_response("Endpoint not found.", 404, is_error=True)

        response_body = response_html.encode('utf-8')
    
    start_response(status, headers)
    return [response_body]

# ----- MAIN SERVER MANAGER CLASS (Keep the logic mostly the same) -----
class Server:
    # ... (Keep all existing methods like __init__, _generate_token_name, load_server_index_json, 
    # _generate_server_index_json, list_servers, format_server_list, kill_server, 
    # validate_token_and_kill, remove_from_index exactly as they were.)
    
    def __init__(self) -> None:
        # server_index maps {port_str: {"token": str, "pid": int}, ...}
        self.server_index: ServerIndex = {}
        self.token_length = 10
        self.json_file = 'server/server1.json'
        
        # Ensure the server directory exists and load data
        os.makedirs(os.path.dirname(self.json_file), exist_ok=True)
        self.load_server_index_json()

    def _generate_token_name(self) -> str:
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(self.token_length))
    
    def load_server_index_json(self):
        try:
            with open(self.json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
                # Ensure data conforms to the expected structure
                self.server_index = {
                    str(p): {"token": info.get("token", ""), "pid": info.get("pid", 0)} 
                    for p, info in data.items() 
                    if isinstance(info, dict) and "token" in info
                }
                print(f"{COLOR_INFO}Server index loaded successfully.{COLOR_RESET}")
        except FileNotFoundError:
            self.server_index = {}
            print(f"{COLOR_WARNING}No server index file found at '{self.json_file}'. Starting fresh.{COLOR_RESET}")
        except json.JSONDecodeError:
            self.server_index = {}
            raise ServerDataBaseError(f"{COLOR_ERROR}Error decoding server index JSON. File might be corrupted.{COLOR_RESET}")
        except Exception as e:
            self.server_index = {}
            raise ServerDataBaseError(f"{COLOR_ERROR}Error loading server index JSON: {e}{COLOR_RESET}")

    def _generate_server_index_json(self):
        try:
            with open(self.json_file, 'w', encoding='utf-8') as file:
                json.dump(self.server_index, file, indent=4)
        except Exception as e:
            print(f"{COLOR_ERROR}Error saving server index JSON: {e}{COLOR_RESET}")
            raise ServerDataBaseError(f"Error uploading server index JSON")

    def start_server(self, port: int, id: int):
        port_str = str(port)
        
        # --- LOGIC TO START A SERVER IN A SEPARATE PROCESS (UNCHANGED) ---
        
        # If the process is a SUBPROCESS started by the manager, it runs the code below.
        # Note: The subprocess still uses http.server.SimpleHTTPRequestHandler, as it's the
        # server we are managing/spawning, not the manager itself.
        if len(sys.argv) > 1 and sys.argv[1].lower() == 'start':
            # This is the subprocess. We proceed with the original serving logic.
            
            if port_str in self.server_index:
                # Re-check in the subprocess (just in case)
                raise ServerExists(f"Server with port {port} already exists in the index.")
            
            token = self._generate_token_name()
            
            # Set up the index entry BEFORE starting the server process
            current_pid = os.getpid()
            self.server_index[port_str] = {"token": token, "pid": current_pid}
            self._generate_server_index_json()

            global server_manager
            server_manager = self 

            # The CustomHandler remains as in the original server.py
            # --------------------------------------------------------
            class CustomHandler(http.server.SimpleHTTPRequestHandler):
                
                # 1. __init__ (Constructor) - REQUIRED
                def __init__(self, *args, **kwargs):
                    """Initializes the CustomHandler, ensuring SimpleHTTPRequestHandler's __init__ is called."""
                    super().__init__(*args, **kwargs)

                # 2. log_request - RECOMMENDED (Prevents excessive console spam)
                def log_request(self, code='-', size='-'):
                    """Overrides the base method to suppress logging for successful static file loads (code 200)."""
                    if code not in [200, 304]:
                        super().log_request(code, size)
                    
                # Helper function to send an error response
                def _send_error_response(self, code, message):
                    self.send_response(code)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    cleaned_message = _strip_color_codes(message)
                    response_html = f"<h1 style='color: #ff6363;'>ERROR {code}: {cleaned_message}</h1>"
                    self.wfile.write(response_html.encode('utf-8'))

                # Helper function to send a success response (updated to handle code_style)
                def _send_success_response(self, message: str, code_style: bool = False):
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    
                    cleaned_message = _strip_color_codes(message)
                    
                    if code_style:
                        response_html = f"<pre style='background-color: #2e4747; color: white; border: none; padding: 0;'>{cleaned_message}</pre>"
                    else:
                        response_html = f"<h1 style='color: #5cb85c;'>{cleaned_message}</h1>"
                        
                    self.wfile.write(response_html.encode('utf-8'))

                # 3. do_POST - Handles only the internal server kill-by-token and manager actions
                def do_POST(self):
                    global server_manager, running_server_httpd
                    
                    try:
                        content_length = int(self.headers.get('Content-Length', 0))
                        if content_length == 0:
                            raise ServerPOSTError("No content received.")
                            
                        post_data = self.rfile.read(content_length).decode('utf-8')
                        parsed_data = urllib.parse.parse_qs(post_data)
                    
                    except Exception as e:
                        print(f"{COLOR_ERROR}[{port}] POST Data Read Error: {e}{COLOR_RESET}")
                        self._send_error_response(500, "Failed to read POST data.")
                        return

                    
                    # --- Internal Server Kill (/submit) ---
                    if self.path == '/submit':
                        token = parsed_data.get('token', [''])[0].strip()
                        command = parsed_data.get('command', [''])[0].strip().lower()

                        if command == 'kill':
                            if server_manager.validate_token_and_kill(token):
                                # Start a thread to shut down the HTTP server cleanly
                                threading.Thread(target=running_server_httpd.shutdown).start()
                                self._send_success_response("SUCCESS: Server shutting down by token.")
                            else:
                                self._send_error_response(403, "Access Denied: Invalid token.")
                        else:
                            self._send_error_response(400, "Unknown command.")

                    # --- NEW: Manager Actions (/manager-action) ---
                    # NOTE: This part is technically duplicated from the WSGI app above, 
                    # but it's essential if a running managed server is ALSO used as a manager.
                    # We'll keep the original logic here for completeness of the spawned server.
                    # For this rewrite, we assume the WSGI app is the main manager.
                    elif self.path == '/manager-action':
                        try:
                            action = parsed_data.get('action', [''])[0].strip().lower()
                            identifier = parsed_data.get('identifier', [''])[0].strip()
                            
                            # START
                            if action == 'start':
                                if not identifier or ':' not in identifier:
                                    raise ServerManagerActionError("Invalid identifier format for start. Must be 'port:id'.")
                                
                                port_str, id_str = identifier.split(':')
                                port_sub = int(port_str)
                                id_sub = int(id_str)
                                
                                # Execute the start command in a new background process
                                command = [sys.executable, os.path.abspath(__file__), 'start', port_str, id_str]
                                subprocess.Popen(command, close_fds=True, start_new_session=True)

                                self._send_success_response(f"SUCCESS: Server start command dispatched for port {port_sub}. Check terminal for PID and token.", code_style=True)
                                
                            # KILL
                            elif action == 'kill':
                                if not identifier:
                                    raise ServerManagerActionError("Kill Error: Port or Token identifier is required.")

                                with captured_output() as (out, err):
                                    try:
                                        server_manager.kill_server(identifier)
                                        output_message = out.getvalue().strip()
                                        if "successfully removed from index" in output_message:
                                            self._send_success_response(output_message, code_style=True)
                                        else:
                                            self._send_success_response(output_message, code_style=True)

                                    except ServerNotFound as e:
                                        self._send_error_response(404, str(e))
                                    except ServerKillError as e:
                                        self._send_error_response(500, str(e))
                            
                            # LIST
                            elif action == 'list':
                                with captured_output() as (out, err):
                                    server_manager.list_servers()
                                
                                output_message = out.getvalue().strip()
                                self._send_success_response(output_message, code_style=True)
                                
                            else:
                                raise ServerManagerActionError(f"Unknown manager action: {action}")
                                
                        except ServerManagerActionError as e:
                            print(f"{COLOR_ERROR}[{port}] Manager Action Error: {e}{COLOR_RESET}")
                            self._send_error_response(400, str(e))
                        except Exception as e:
                            print(f"{COLOR_ERROR}[{port}] Unexpected Manager Action Error: {e}{COLOR_RESET}")
                            self._send_error_response(500, f"An unexpected server error occurred: {e}")

                    # --- END: Manager Actions ---
                    
                    else:
                        self._send_error_response(404, "Endpoint not found.")

                # The existing do_GET method must remain here
                def do_GET(self):
                    super().do_GET()
            # --------------------------------------------------------

            Handler = CustomHandler
            # ... (Rest of the start_server logic for the subprocess is unchanged)
            def shutdown_server_signal(signum, frame):
                print(f"\n{COLOR_WARNING}[{port}] Received termination signal. Closing server...{COLOR_RESET}")
                global running_server_httpd
                if running_server_httpd:
                    running_server_httpd.shutdown()
                
                # Clean up index on manual exit
                if port_str in self.server_index:
                    del self.server_index[port_str]
                    self._generate_server_index_json()
                sys.exit(0)

            signal.signal(signal.SIGINT, shutdown_server_signal)

            try:
                with socketserver.TCPServer(("", port), Handler) as httpd:
                    global running_server_httpd
                    running_server_httpd = httpd
                    
                    print(f"{COLOR_SUCCESS}Serving at port {port} with PID {current_pid} and token {token}{COLOR_RESET}")
                    print(f"{COLOR_INFO}http://localhost:{port}{COLOR_RESET}")
                    
                    httpd.serve_forever()
                    
            except OSError as e:
                if "Address already in use" in str(e):
                    print(f"{COLOR_ERROR}ERROR: Port {port} is already in use by another application.{COLOR_RESET}")
                    if port_str in self.server_index:
                        del self.server_index[port_str]
                        self._generate_server_index_json()
                    sys.exit(1)
                else:
                    print(f"{COLOR_ERROR}An OS error occurred: {e}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}An unexpected error occurred: {e}{COLOR_RESET}")
            finally:
                print(f"{COLOR_INFO}[{port}] Server process finished.{COLOR_RESET}")
                if port_str in self.server_index:
                    del self.server_index[port_str]
                    self._generate_server_index_json()
        
    def list_servers(self):
        # ... (Unchanged)
        self.load_server_index_json()
        if not self.server_index:
            print(f"{COLOR_WARNING}No active servers indexed.{COLOR_RESET}")
            return
        
        print(f"{COLOR_INFO}{Style.BRIGHT}Active servers indexed:{COLOR_RESET}")
        for port, info in self.server_index.items():
            print(f"  {Fore.WHITE}Port: {COLOR_SUCCESS}{port}{COLOR_RESET}, {Fore.WHITE}PID: {COLOR_INFO}{info['pid']}{COLOR_RESET}, {Fore.WHITE}Token: {COLOR_DEBUG}{info['token']}{COLOR_RESET}")

    def format_server_list(self):
        # ... (Unchanged)
        try:
            self.server_index = {}
            self._generate_server_index_json()
            print(f"{COLOR_SUCCESS}Server index formatted and cleared successfully.{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_ERROR}Error formatting server list: {e}{COLOR_RESET}")

    def kill_server(self, identifier: str):
        # ... (Unchanged)
        self.load_server_index_json()

        port_to_kill = None
        server_info: Optional[ServerInfo] = None
        
        if identifier in self.server_index:
            port_to_kill = identifier
            server_info = self.server_index[identifier]
        else:
            for port, info in self.server_index.items():
                if info["token"] == identifier:
                    port_to_kill = port
                    server_info = info
                    break
        
        if not port_to_kill or not server_info:
            raise ServerNotFound(f"No server found with identifier: {identifier}")

        pid_to_kill = server_info["pid"]
        
        if pid_to_kill and pid_to_kill > 0:
            try:
                proc = psutil.Process(pid_to_kill)
                proc_name = proc.name()
                print(f"{COLOR_WARNING}Attempting to kill PID {pid_to_kill} ({proc_name}) associated with port {port_to_kill}...{COLOR_RESET}")
                
                proc.terminate()
                
                try:
                    proc.wait(timeout=3)
                    print(f"{COLOR_SUCCESS}Process PID {pid_to_kill} terminated successfully.{COLOR_RESET}")
                except psutil.TimeoutExpired:
                    proc.kill()
                    print(f"{COLOR_WARNING}Process PID {pid_to_kill} forcefully killed (Timeout).{COLOR_RESET}")
                
            except psutil.NoSuchProcess:
                print(f"{COLOR_WARNING}Warning: PID {pid_to_kill} not found. Process may have already exited.{COLOR_RESET}")
            except Exception as e:
                raise ServerKillError(f"Error killing process PID {pid_to_kill}: {e}")
        else:
             print(f"{COLOR_WARNING}Warning: PID for port {port_to_kill} not found in index. Skipping process kill.{COLOR_RESET}")
        
        if port_to_kill in self.server_index:
            del self.server_index[port_to_kill]
            self._generate_server_index_json()
            print(f"{COLOR_SUCCESS}Server on port {port_to_kill} successfully removed from index.{COLOR_RESET}")
        else:
            raise ServerNotFound(f"Server index cleanup failed for {port_to_kill}")
        
    def validate_token_and_kill(self, token: str) -> bool:
        # ... (Unchanged)
        if not token:
            return False

        server_port_str = None
        for port_str, info in self.server_index.items():
            if info.get("token") == token:
                server_port_str = port_str
                break

        if server_port_str:
            self.remove_from_index(server_port_str)
            return True
        else:
            return False

    def remove_from_index(self, port_str: str):
        # ... (Unchanged)
        if port_str in self.server_index:
            del self.server_index[port_str]
            self._generate_server_index_json()


# ----- MAIN EXECUTION BLOCK -----
if __name__ == "__main__":
    print(f"{COLOR_INFO}waitress{COLOR_RESET}")
    manager = Server()
    server_manager = manager 
    
    # Check if a command-line argument is provided (for manager console actions or subprocess start)
    if len(sys.argv) >= 2:
        command = sys.argv[1].lower()
        
        if command == "start":
            # This logic executes if the manager successfully spawns a child process
            if len(sys.argv) == 4:
                try:
                    port = int(sys.argv[2])
                    id = int(sys.argv[3]) 
                    # The start_server method handles the subprocess's server logic
                    manager.start_server(port, id) 
                except ValueError:
                    print(f"{COLOR_ERROR}Error: Port and ID must be integers.{COLOR_RESET}")
                except ServerExists as e:
                    print(f"{COLOR_WARNING}{e}{COLOR_RESET}")
                except ServerDataBaseError as e:
                    print(f"{COLOR_ERROR}{e}{COLOR_RESET}")
                except Exception as e:
                    print(f"{COLOR_ERROR}An unexpected error occurred: {e}{COLOR_RESET}")
            else:
                print(f"{COLOR_INFO}Usage: python waitress_server_manager.py start <port> <id>{COLOR_RESET}")
        
        elif command == "kill":
            if len(sys.argv) == 3:
                identifier = sys.argv[2]
                try:
                    manager.kill_server(identifier)
                except ServerNotFound as e:
                    print(f"{COLOR_WARNING}{e}{COLOR_RESET}")
                except ServerKillError as e:
                    print(f"{COLOR_ERROR}{e}{COLOR_RESET}")
            else:
                print(f"{COLOR_INFO}Usage: python waitress_server_manager.py kill <port | token>{COLOR_RESET}")
                
        elif command == "list":
            manager.list_servers()
            
        elif command == "format":
            manager.format_server_list()
            
        else:
            print(f"{COLOR_WARNING}Unknown command: '{command}'{COLOR_RESET}")
            print(f"{COLOR_INFO}Usage: python waitress_server_manager.py <start | kill | list | format> ...{COLOR_RESET}")
            sys.exit(1)

    # If no command-line arguments are provided, start the Waitress Manager Dashboard
    else:
        MANAGER_PORT = 8000 # Default port for the Manager Dashboard
        print(f"{COLOR_SUCCESS}Starting Waitress Server Manager Dashboard on port {MANAGER_PORT}...{COLOR_RESET}")
        print(f"{COLOR_INFO}Access dashboard at: http://localhost:{MANAGER_PORT}{COLOR_RESET}")
        
        try:
            # Waitress will serve the manager_wsgi_app
            serve(manager_wsgi_app, host='0.0.0.0', port=MANAGER_PORT)
        except OSError as e:
            print(f"{COLOR_ERROR}ERROR: Failed to start Waitress server: {e}{COLOR_RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{COLOR_ERROR}An unexpected error occurred during Waitress startup: {e}{COLOR_RESET}")
            sys.exit(1)