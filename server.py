# ----- IMPORTING ALL REQUIRMENTS -----
from extra import host_ip

import http.server
import socketserver
import random
import string
import json
import sys
import signal
import os
import urllib.parse
import threading # For cleaner server shutdown
import psutil    # For platform-independent process management (REQUIRES: pip install psutil)
from typing import Dict, Any, Optional
import contextlib
import subprocess # For running external commands
from io import StringIO
from colorama import init, Fore, Style, Back
import re # NEW: Import for regular expressions to strip color codes

# Initialize Colorama for cross-platform support. autoreset=True is very helpful!
init(autoreset=True)

# Define color variables for consistency
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
running_server_httpd: socketserver.TCPServer = None


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
class ServerManagerActionError(ServerErrors): pass # NEW: For errors during manager POST actions


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


def run_subprocess_command(command: list) -> str:
    """Runs an external command and captures its output."""
    try:
        # We use Popen and communicate for cleaner, non-blocking process management
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merge stderr into stdout
            text=True,
            bufsize=1,
            close_fds=True,
            shell=False
        )
        
        # NOTE: We can't wait for the process here if the command is 'start', 
        # as the start command is designed to run forever (httpd.serve_forever()).
        # We only need the process to start successfully.
        
        # For 'start' command, we just return a success message and the command.
        if command[1].lower() == 'start':
            # The actual output and PID will be logged by the subprocess itself
            return f"{COLOR_INFO}Server start command dispatched: {' '.join(command)}{COLOR_RESET}"
        
        # For 'list' or 'kill' (if we were running them as subprocesses)
        # However, for a web-based manager, we run kill/list directly in the manager process
        # so this part is technically unnecessary for the current web-manager structure,
        # but it's a good general helper for running external subprocesses.
        
        stdout, _ = process.communicate(timeout=10)
        return stdout
        
    except subprocess.TimeoutExpired:
        if 'process' in locals() and process.poll() is None:
            process.kill()
        return f"{COLOR_ERROR}Command execution timed out after 10 seconds.{COLOR_RESET}"
    except FileNotFoundError:
        return f"{COLOR_ERROR}Error: Python executable not found or command not recognized.{COLOR_RESET}"
    except Exception as e:
        return f"{COLOR_ERROR}An error occurred while running command: {e}{COLOR_RESET}"


# Helper function to remove ALL Colorama/ANSI escape codes
def _strip_color_codes(message: str) -> str:
    # This regex is designed to catch standard ANSI escape sequences
    # \x1b is the escape character (octal \033)
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', message)


# ----- MAIN SERVER MANAGER CLASS -----
class Server:
    def __init__(self) -> None:
        # server_index maps {port_str: {"token": str, "pid": int}, ...}
        self.server_index: ServerIndex = {}
        self.token_length = 10
        self.json_file = 'server/server.json'
        
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
        
        # This function is now only called via the command line or the web manager action.
        
        # If the process is a SUBPROCESS started by the manager, it runs the code below.
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

            # Replace your entire CustomHandler class with this code
            class CustomHandler(http.server.SimpleHTTPRequestHandler):
                
                # 1. __init__ (Constructor) - REQUIRED
                def __init__(self, *args, **kwargs):
                    """Initializes the CustomHandler, ensuring SimpleHTTPRequestHandler's __init__ is called."""
                    super().__init__(*args, **kwargs)

                # 2. log_request - RECOMMENDED (Prevents excessive console spam)
                def log_request(self, code='-', size='-'):
                    """Overrides the base method to suppress logging for successful static file loads (code 200)."""
                    # Only log errors, POSTs, and non-standard statuses
                    if code not in [200, 304]:
                        super().log_request(code, size)
                    
                # Helper function to send an error response
                def _send_error_response(self, code, message):
                    self.send_response(code)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    # *** MODIFICATION START ***
                    # Use a standard string for the web message, stripping terminal color codes
                    # HTML color for the web response
                    # Use the new helper function to strip all color codes
                    cleaned_message = _strip_color_codes(message)
                    response_html = f"<h1 style='color: #ff6363;'>ERROR {code}: {cleaned_message}</h1>"
                    # *** MODIFICATION END ***
                    self.wfile.write(response_html.encode('utf-8'))

                # Helper function to send a success response (updated to handle code_style)
                def _send_success_response(self, message: str, code_style: bool = False):
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    
                    # *** MODIFICATION START ***
                    # Strip all colorama/ANSI codes before sending to the web
                    # Use the new helper function to strip all color codes
                    cleaned_message = _strip_color_codes(message)
                    
                    if code_style:
                        # Use pre for code style output (like the server list)
                        response_html = f"<pre style='background-color: #2e4747; color: white; border: none; padding: 0;'>{cleaned_message}</pre>"
                    else:
                        # Simple H1 for status messages
                        response_html = f"<h1 style='color: #5cb85c;'>{cleaned_message}</h1>"
                        
                    # *** MODIFICATION END ***
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
                        # Handler for a server killing itself by its own token
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
                    elif self.path == '/manager-action':
                        try:
                            action = parsed_data.get('action', [''])[0].strip().lower()
                            identifier = parsed_data.get('identifier', [''])[0].strip() # Port, token, or 'port:id'
                            
                            if action == 'start':
                                if not identifier or ':' not in identifier:
                                    raise ServerManagerActionError("Invalid identifier format for start. Must be 'port:id'.")
                                
                                try:
                                    # The manager server will execute a command like:
                                    # python server1.py start <port> <id>
                                    port_str, id_str = identifier.split(':')
                                    port = int(port_str)
                                    id = int(id_str)
                                    
                                    # Execute the start command in a new background process
                                    command = [sys.executable, os.path.abspath(__file__), 'start', port_str, id_str]
                                    
                                    # We don't need the output, just need the command to run.
                                    # For a truly robust system, this should use daemonization, 
                                    # but for this script, we use Popen to decouple.
                                    subprocess.Popen(command, close_fds=True, start_new_session=True)

                                    self._send_success_response(f"SUCCESS: Server start command dispatched for port {port}. Check terminal for PID and token.", code_style=True)
                                    
                                except (ValueError, ServerExists, ServerDataBaseError) as e:
                                    # Catch specific errors from the command-line execution path
                                    raise ServerManagerActionError(f"Start Error: {e}")
                                
                            elif action == 'kill':
                                if not identifier:
                                    raise ServerManagerActionError("Kill Error: Port or Token identifier is required.")

                                # Use captured_output to get the output of the kill_server method
                                with captured_output() as (out, err):
                                    # This output will contain colorama codes as it's terminal output
                                    try:
                                        server_manager.kill_server(identifier)
                                        output_message = out.getvalue().strip()
                                        
                                        # Process the captured output (this will contain the success/warning messages)
                                        # Check if it seems successful (this is a heuristic, a robust API would return JSON)
                                        if "successfully removed from index" in output_message:
                                            self._send_success_response(output_message, code_style=True)
                                        else:
                                            # If there was a warning (e.g., PID not found), send it as a success with warning text
                                            self._send_success_response(output_message, code_style=True)

                                    except ServerNotFound as e:
                                        # If kill_server raises a ServerNotFound, capture the message
                                        self._send_error_response(404, str(e))
                                    except ServerKillError as e:
                                        # If kill_server raises a ServerKillError, capture the message
                                        self._send_error_response(500, str(e))
                                

                            elif action == 'list':
                                # Use captured_output to get the output of the list_servers method
                                with captured_output() as (out, err):
                                    server_manager.list_servers()
                                
                                output_message = out.getvalue().strip()
                                self._send_success_response(output_message, code_style=True)
                                
                            else:
                                raise ServerManagerActionError(f"Unknown manager action: {action}")
                                
                        except ServerManagerActionError as e:
                            print(f"{COLOR_ERROR}[{port}] Manager Action Error: {e}{COLOR_RESET}")
                            # The error message should be clean enough to send back
                            self._send_error_response(400, str(e))
                        except Exception as e:
                            print(f"{COLOR_ERROR}[{port}] Unexpected Manager Action Error: {e}{COLOR_RESET}")
                            self._send_error_response(500, f"An unexpected server error occurred: {e}")

                    # --- END: Manager Actions ---
                    
                    else:
                        self._send_error_response(404, "Endpoint not found.")

                # The existing do_GET method must remain here
                def do_GET(self):
                    # Serve the files (like index.html) as before
                    super().do_GET()
            
            Handler = CustomHandler

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
                    print(f'{COLOR_INFO}computer ip: {host_ip()['localIP']}\t{host_ip()['localIP']}:{port}{COLOR_RESET}')
                    
                    httpd.serve_forever()
                    
            except OSError as e:
                if "Address already in use" in str(e):
                    # NOTE: This error might happen in the subprocess.
                    # This must also be a ServerExists exception now.
                    print(f"{COLOR_ERROR}ERROR: Port {port} is already in use by another application.{COLOR_RESET}")
                    # Remove the entry created before we started
                    if port_str in self.server_index:
                        del self.server_index[port_str]
                        self._generate_server_index_json()
                    sys.exit(1) # Exit with an error code
                else:
                    print(f"{COLOR_ERROR}An OS error occurred: {e}{COLOR_RESET}")
            except Exception as e:
                print(f"{COLOR_ERROR}An unexpected error occurred: {e}{COLOR_RESET}")
            finally:
                print(f"{COLOR_INFO}[{port}] Server process finished.{COLOR_RESET}")
                # Ensure index cleanup if the server dies for any reason
                if port_str in self.server_index:
                    del self.server_index[port_str]
                    self._generate_server_index_json()
        
        # --- END NEW LOGIC ---

    def list_servers(self):
        self.load_server_index_json()
        if not self.server_index:
            # Print a consistent formatted message for the web output
            print(f"{COLOR_WARNING}No active servers indexed.{COLOR_RESET}")
            return
        
        print(f"{COLOR_INFO}{Style.BRIGHT}Active servers indexed:{COLOR_RESET}")
        for port, info in self.server_index.items():
            # Highlight important info: Port in green, PID in cyan, Token in magenta
            print(f"  {Fore.WHITE}Port: {COLOR_SUCCESS}{port}{COLOR_RESET}, {Fore.WHITE}PID: {COLOR_INFO}{info['pid']}{COLOR_RESET}, {Fore.WHITE}Token: {COLOR_DEBUG}{info['token']}{COLOR_RESET}")

    def format_server_list(self):
        try:
            # Removed load_server_index_json() as the goal is to clear it
            self.server_index = {}
            self._generate_server_index_json()
            print(f"{COLOR_SUCCESS}Server index formatted and cleared successfully.{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_ERROR}Error formatting server list: {e}{COLOR_RESET}")

    def kill_server(self, identifier: str):
        """Kills a server process based on its indexed port or token."""
        self.load_server_index_json()

        port_to_kill = None
        server_info: Optional[ServerInfo] = None
        
        # 1. Find the port and server info using the identifier (port or token)
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
        
        # 2. Terminate the process using the stored PID (Primary method)
        if pid_to_kill and pid_to_kill > 0:
            try:
                proc = psutil.Process(pid_to_kill)
                proc_name = proc.name()
                print(f"\n{COLOR_WARNING}[{port_to_kill}] Received termination signal. Closing server...{COLOR_RESET}")
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
                # We still clean up the index even if the process is gone
            except Exception as e:
                raise ServerKillError(f"Error killing process PID {pid_to_kill}: {e}")
        else:
             print(f"{COLOR_WARNING}Warning: PID for port {port_to_kill} not found in index. Skipping process kill.{COLOR_RESET}")
        
        # 3. Clean up the server index
        if port_to_kill in self.server_index:
            del self.server_index[port_to_kill]
            self._generate_server_index_json()
            print(f"{COLOR_SUCCESS}Server on port {port_to_kill} successfully removed from index.{COLOR_RESET}")
        else:
            # NOTE: This error should ideally not happen if the earlier checks were successful, 
            # but it is good to keep for robustness.
            raise ServerNotFound(f"Server index cleanup failed for {port_to_kill}")
        
    def validate_token_and_kill(self, token: str) -> bool:
        """
        Validates the token against the active server index.
        If valid, it removes the server from the index.
        It does NOT kill the OS process here; the handler does that after this returns True.
        
        Returns:
            bool: True if the token is valid and the server entry was removed, False otherwise.
        """
        if not token:
            return False

        # Find the server in the index by its token
        server_port_str = None
        for port_str, info in self.server_index.items():
            if info.get("token") == token:
                server_port_str = port_str
                break

        if server_port_str:
            # The token is valid. Remove the entry from the index.
            # We don't need to kill the process here, as the server's own
            # shutdown() call (in the handler) will terminate the process.
            self.remove_from_index(server_port_str)
            return True
        else:
            # Token not found or invalid
            return False

    def remove_from_index(self, port_str: str):
        """Removes a server entry from the index and saves the database."""
        # Need to re-add the save_index method that was presumably removed
        def save_index(self):
            self._generate_server_index_json()
            
        if port_str in self.server_index:
            del self.server_index[port_str]
            self._generate_server_index_json() # Use the existing generate method

if __name__ == "__main__":
    manager = Server()
    server_manager = manager 
    
    if len(sys.argv) >= 2:
        command = sys.argv[1].lower()
        
        if command == "start":
            if len(sys.argv) == 4:
                try:
                    port = int(sys.argv[2])
                    id = int(sys.argv[3]) 
                    # The manager.start_server logic is now a mix: 
                    # If this is a subprocess, it runs the server.
                    # If called directly from the main process without subprocess, it fails (which is fine).
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
                print(f"{COLOR_INFO}Usage: python server.py start <port> <id>{COLOR_RESET}")
        
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
                print(f"{COLOR_INFO}Usage: python server.py kill <port | token>{COLOR_RESET}")
                
        elif command == "list":
            manager.list_servers()
            
        elif command == "format":
            manager.format_server_list()
            
        else:
            print(f"{COLOR_WARNING}Unknown command: '{command}'{COLOR_RESET}")
            print(f"{COLOR_INFO}Usage: python server.py <start | kill | list | format> ...{COLOR_RESET}")
            sys.exit(1)
    else:
        print(f"{COLOR_INFO}Usage: python server.py <start | kill | list | format> ...{COLOR_RESET}")
        sys.exit(1)