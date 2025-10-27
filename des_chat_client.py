import socket
import threading
from DES_HEX import encrypt, decrypt, bits_to_binary_string, binary_string_to_bits

HOST = 'localhost'
PORT = 12345

def sender_mode(sock):
    """Sender: input message + key, send to server"""
    while True:
        msg = input("Enter message (or 'quit' to exit): ").strip()
        if msg.lower() == "quit":
            sock.send("quit".encode('utf-8'))
            break

        while True:
            key = input("Enter 8-char key: ").strip()
            if len(key) != 8:
                print("Key must be exactly 8 characters.")
                continue
            break

        try:
            cipher_bits = encrypt(msg, key)
            key_bits = []
            for ch in key:
                bits = format(ord(ch), '08b')
                key_bits.extend(int(b) for b in bits)

            key_bits_str = bits_to_binary_string(key_bits)
            cipher_bits_str = bits_to_binary_string(cipher_bits)
            combined = f"{key_bits_str}::{cipher_bits_str}"
            sock.send(combined.encode('utf-8'))
            print("[INFO] Encrypted bits sent.")
        except Exception as e:
            print(f"[ERROR] Encryption failed: {e}")

def receiver_mode(sock):
    """Receiver: decrypt incoming messages automatically"""
    print("[RECEIVER] Waiting for incoming encrypted messages...")

    while True:
        try:
            data = sock.recv(8192).decode('utf-8')
            if not data:
                print("[!] Disconnected from server.")
                break

            if "::" not in data:
                print(data)
                continue

            try:
                key_bits_str, cipher_bits_str = data.split("::", 1)
                key_bits = binary_string_to_bits(key_bits_str)
                cipher_bits = binary_string_to_bits(cipher_bits_str)
                key = ''.join(chr(int(''.join(map(str, key_bits[i:i+8])), 2)) for i in range(0, len(key_bits), 8))
                decrypted = decrypt(cipher_bits, key)
                print(f"\n[DECRYPTED MESSAGE]: {decrypted}")
            except Exception as e:
                print(f"[!] Failed to decrypt message: {e}")

        except ConnectionResetError:
            print("[!] Server disconnected.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
        nickname = input("Enter username: ").strip()
        sock.send(nickname.encode('utf-8'))

        first_msg = sock.recv(1024).decode('utf-8')
        print(first_msg)

        # Assign Sender or Receiver
        if "sender" in first_msg.lower():
            sender_mode(sock)
        elif "receiver" in first_msg.lower():
            receiver_mode(sock)
        else:
            # waiting message
            while True:
                msg = sock.recv(1024).decode('utf-8')
                print(msg)
                if "sender" in msg.lower() or "receiver" in msg.lower():
                    if "sender" in msg.lower():
                        sender_mode(sock)
                    else:
                        receiver_mode(sock)
                    break

    except ConnectionRefusedError:
        print("[!] Cannot connect to server.")
    except KeyboardInterrupt:
        print("\n[!] Client closed manually.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
