import socket
import threading
from DES_HEX import binary_string_to_bits, bits_to_binary_string

class DESServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.clients = []
        self.nicknames = []
        self.lock = threading.Lock()

    def handle_client(self, client):
        """Handle client connection"""
        try:
            nickname = client.recv(1024).decode('utf-8')
            if not nickname:
                client.close()
                return

            with self.lock:
                self.clients.append(client)
                self.nicknames.append(nickname)

            print(f"[+] {nickname} connected.")

            if len(self.clients) < 2:
                client.send("Waiting for another user to join...\n".encode('utf-8'))
                while len(self.clients) < 2:
                    pass  # wait until second client joins
                client.send("Both users connected!\n".encode('utf-8'))
            else:
                self.start_chat()

        except Exception as e:
            print(f"[!] Error handling client: {e}")
            self.remove_client(client)

    def start_chat(self):
        """Forward encrypted bits from sender -> receiver"""
        sender, receiver = self.clients
        sender_name, receiver_name = self.nicknames

        sender.send(f"You are the sender. Your partner is {receiver_name}.\n".encode('utf-8'))
        receiver.send(f"You are the receiver. Waiting for messages from {sender_name}...\n".encode('utf-8'))

        print("[#] Chat session started.\n")

        while True:
            try:
                data = sender.recv(8192).decode('utf-8')
                if not data:
                    print("[!] Sender disconnected.")
                    break

                if data.lower() == "quit":
                    print("[#] Sender ended the chat.")
                    break

                # format: <key_bits>::<cipher_bits>
                if "::" not in data:
                    receiver.send("[!] Invalid data format received.\n".encode('utf-8'))
                    continue

                try:
                    key_bits_str, cipher_bits_str = data.split("::", 1)

                    # Validasi agar tidak error parsing
                    binary_string_to_bits(key_bits_str)
                    binary_string_to_bits(cipher_bits_str)

                    # 🔹 Logging kiriman dari user
                    print(f"From : {sender_name}")
                    print(f"Message : {cipher_bits_str[:80]}{'...' if len(cipher_bits_str) > 80 else ''}")
                    print(f"Key : {key_bits_str}\n")

                except Exception:
                    receiver.send("[!] Invalid binary format.\n".encode('utf-8'))
                    continue

                # Kirim langsung ke receiver
                receiver.send(f"{key_bits_str}::{cipher_bits_str}".encode('utf-8'))

            except ConnectionResetError:
                print("[!] Connection reset by sender.")
                break
            except Exception as e:
                print(f"[!] Chat loop error: {e}")
                break

        self.shutdown()

    def remove_client(self, client):
        """Remove disconnected client"""
        if client in self.clients:
            idx = self.clients.index(client)
            name = self.nicknames[idx]
            self.clients.pop(idx)
            self.nicknames.pop(idx)
            print(f"[-] {name} disconnected.")

    def shutdown(self):
        """Close all connections"""
        for c in self.clients:
            try:
                c.close()
            except:
                pass
        self.clients.clear()
        self.nicknames.clear()
        print("[#] Server reset, session ended.\n")

    def start_server(self):
        """Start the server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(2)
        print(f"[SERVER] Running on {self.host}:{self.port}")

        while True:
            if len(self.clients) >= 2:
                continue
            client, _ = server.accept()
            threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    DESServer().start_server()
