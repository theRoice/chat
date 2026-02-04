import socket
import random
import threading
import queue
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from datetime import datetime


def modular_exponentiation(base_value: int, exponent_value: int, modulus_value: int) -> int:
    """
    Compute (base_value ** exponent_value) % modulus_value efficiently using square-and-multiply.
    No crypto libraries used.
    """
    if modulus_value == 1:
        return 0

    result_value = 1
    base_value = base_value % modulus_value
    current_exponent = exponent_value

    while current_exponent > 0:
        if current_exponent & 1:
            result_value = (result_value * base_value) % modulus_value
        base_value = (base_value * base_value) % modulus_value
        current_exponent >>= 1

    return result_value


def extended_gcd(left_value: int, right_value: int) -> tuple[int, int, int]:
    """
    Returns (gcd, x, y) such that left_value*x + right_value*y = gcd.
    """
    if right_value == 0:
        return (left_value, 1, 0)

    gcd_value, x1, y1 = extended_gcd(right_value, left_value % right_value)
    x_value = y1
    y_value = x1 - (left_value // right_value) * y1
    return (gcd_value, x_value, y_value)


def modular_inverse(value: int, modulus_value: int) -> int:
    """
    Compute the multiplicative inverse of value mod modulus_value.
    Raises ValueError if inverse does not exist.
    """
    gcd_value, x_value, _ = extended_gcd(value, modulus_value)
    if gcd_value != 1:
        raise ValueError("No modular inverse exists (gcd != 1).")
    return x_value % modulus_value


def is_probable_prime(candidate_value: int, rounds_count: int = 24) -> bool:
    """
    Miller-Rabin probabilistic primality test (from scratch).
    Good enough for classroom/demo RSA, without using crypto libraries.
    """
    if candidate_value < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for small_prime in small_primes:
        if candidate_value == small_prime:
            return True
        if candidate_value % small_prime == 0:
            return False

    # Write candidate_value - 1 = d * 2^s with d odd
    d_value = candidate_value - 1
    s_value = 0
    while d_value % 2 == 0:
        d_value //= 2
        s_value += 1

    for _ in range(rounds_count):
        a_value = random.randrange(2, candidate_value - 2)
        x_value = modular_exponentiation(a_value, d_value, candidate_value)

        if x_value == 1 or x_value == candidate_value - 1:
            continue

        witness_found = True
        for _ in range(s_value - 1):
            x_value = (x_value * x_value) % candidate_value
            if x_value == candidate_value - 1:
                witness_found = False
                break

        if witness_found:
            return False

    return True


def generate_random_prime(bit_count: int) -> int:
    """
    Generate a random prime with the given bit length using Miller-Rabin.
    """
    if bit_count < 16:
        raise ValueError("Prime bit length too small for RSA demo; use at least 16 bits.")

    while True:
        candidate_value = random.getrandbits(bit_count)
        candidate_value |= (1 << (bit_count - 1))  # ensure top bit set
        candidate_value |= 1  # ensure odd

        if is_probable_prime(candidate_value):
            return candidate_value


def generate_rsa_keypair(prime_bits: int = 512) -> dict:
    """
    Generate RSA keypair from scratch:
      - picks p and q
      - computes n, phi
      - chooses e
      - computes d = e^-1 mod phi
    """
    public_exponent = 65537

    while True:
        p_value = generate_random_prime(prime_bits)
        q_value = generate_random_prime(prime_bits)
        if p_value == q_value:
            continue

        modulus_n = p_value * q_value
        phi_n = (p_value - 1) * (q_value - 1)

        try:
            gcd_value, _, _ = extended_gcd(public_exponent, phi_n)
            if gcd_value != 1:
                continue
            private_exponent = modular_inverse(public_exponent, phi_n)
            return {
                "public_e": public_exponent,
                "public_n": modulus_n,
                "private_d": private_exponent,
            }
        except ValueError:
            continue


# Diffie–Hellman parameters
# RFC 3526 Group 14 (2048-bit MODP prime), generator g = 2.
RFC3526_GROUP14_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

DH_PRIME_P = int(RFC3526_GROUP14_PRIME_HEX, 16)
DH_GENERATOR_G = 2


# GUI Chat Client
CONTROL_PREFIX = "CTRL|"


class TwoClientChatGui:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Two-Client Chat + DH/RSA (No Crypto Libs)")

        # Networking
        self.client_socket: socket.socket | None = None
        self.receive_thread: threading.Thread | None = None
        self.incoming_queue: queue.Queue[str] = queue.Queue()

        # Identity
        self.user_name: str = "User"

        # DH state
        self.dh_private_exponent: int | None = None
        self.dh_public_value: int | None = None
        self.peer_dh_public_value: int | None = None
        self.dh_shared_secret: int | None = None

        # RSA state
        self.rsa_keys: dict | None = None
        self.peer_rsa_public_e: int | None = None
        self.peer_rsa_public_n: int | None = None
        self.rsa_shared_secret: int | None = None

        self._build_gui()
        self._schedule_gui_queue_pump()


    # GUI construction
    def _build_gui(self) -> None:
        self.root.geometry("820x520")

        # Root layout behavior
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        outer_frame = ttk.Frame(self.root, padding=10)
        outer_frame.grid(row=0, column=0, sticky="nsew")

        outer_frame.columnconfigure(0, weight=1)
        outer_frame.rowconfigure(2, weight=1)  # chat section expands

        # Connection Frame
        connection_frame = ttk.LabelFrame(outer_frame, text="Connection", padding=10)
        connection_frame.grid(row=0, column=0, sticky="ew")
        connection_frame.columnconfigure(0, weight=0)  # Host label
        connection_frame.columnconfigure(1, weight=1)  # Host entry expands
        connection_frame.columnconfigure(2, weight=0)  # Port label
        connection_frame.columnconfigure(3, weight=0)  # Port entry stays compact
        connection_frame.columnconfigure(4, weight=0)  # Name label
        connection_frame.columnconfigure(5, weight=1)  # Name entry expands
        connection_frame.columnconfigure(6, weight=0)  # Connect button
        connection_frame.columnconfigure(7, weight=0)  # Spare column
        ttk.Label(connection_frame, text="Host:").grid(row=0, column=0, sticky="w")
        self.host_entry = ttk.Entry(connection_frame)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=(6, 14))

        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky="w")
        self.port_entry = ttk.Entry(connection_frame, width=8)
        self.port_entry.insert(0, "5002")
        self.port_entry.grid(row=0, column=3, sticky="w", padx=(6, 14))

        ttk.Label(connection_frame, text="Name:").grid(row=0, column=4, sticky="w")
        self.name_entry = ttk.Entry(connection_frame)
        self.name_entry.insert(0, "User")
        self.name_entry.grid(row=0, column=5, sticky="ew", padx=(6, 14))

        self.connect_button = ttk.Button(connection_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.grid(row=0, column=6, sticky="w", padx=(6, 0))

        # Key Exchange Frame
        key_frame = ttk.LabelFrame(outer_frame, text="Key Exchange", padding=10)
        key_frame.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        key_frame.columnconfigure(0, weight=0)
        key_frame.columnconfigure(1, weight=0)
        key_frame.columnconfigure(2, weight=1)
        self.dh_button = ttk.Button(
            key_frame,
            text="Generate Diffie–Hellman Secret",
            command=self.start_diffie_hellman
        )
        self.dh_button.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.rsa_button = ttk.Button(
            key_frame,
            text="Generate RSA Secret",
            command=self.start_rsa_secret
        )
        self.rsa_button.grid(row=0, column=1, sticky="w")
        self.status_label = ttk.Label(key_frame, text="Status: Not connected.")
        self.status_label.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        # Chat Frame
        chat_frame = ttk.LabelFrame(outer_frame, text="Chat", padding=10)
        chat_frame.grid(row=2, column=0, sticky="nsew")
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.columnconfigure(1, weight=0)
        chat_frame.columnconfigure(2, weight=0)
        chat_frame.rowconfigure(0, weight=1)
        self.chat_log = ScrolledText(chat_frame, height=18, state="disabled", wrap="word")
        self.chat_log.grid(row=0, column=0, columnspan=3, sticky="nsew")

        # Monospace
        self.chat_log.configure(font=("DejaVu Sans Mono", 10))

        self.message_entry = ttk.Entry(chat_frame)
        self.message_entry.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        self.message_entry.bind("<Return>", lambda _event: self.send_chat_message())

        self.send_button = ttk.Button(chat_frame, text="Send", command=self.send_chat_message)
        self.send_button.grid(row=1, column=1, sticky="w", padx=(10, 0), pady=(10, 0))

        self.quit_button = ttk.Button(chat_frame, text="Quit", command=self.close_and_quit)
        self.quit_button.grid(row=1, column=2, sticky="e", padx=(10, 0), pady=(10, 0))


    def _schedule_gui_queue_pump(self) -> None:
        self.root.after(75, self._drain_incoming_queue)

    def _drain_incoming_queue(self) -> None:
        try:
            while True:
                message = self.incoming_queue.get_nowait()
                self._handle_incoming_text(message)
        except queue.Empty:
            pass
        self._schedule_gui_queue_pump()

    # Logging helpers
    def _append_log(self, line_text: str) -> None:
        self.chat_log.configure(state="normal")
        self.chat_log.insert("end", line_text + "\n")
        self.chat_log.see("end")
        self.chat_log.configure(state="disabled")

    def _set_status(self, status_text: str) -> None:
        self.status_label.configure(text=f"Status: {status_text}")

    # Connection + threads
    def connect_to_server(self) -> None:
        if self.client_socket is not None:
            self._append_log("[local] Already connected.")
            return

        host_value = self.host_entry.get().strip()
        port_value_text = self.port_entry.get().strip()
        name_value = self.name_entry.get().strip() or "User"

        try:
            port_value = int(port_value_text)
        except ValueError:
            self._append_log("[local] Port must be a number.")
            return

        self.user_name = name_value

        try:
            new_socket = socket.socket()
            new_socket.connect((host_value, port_value))
            self.client_socket = new_socket
        except Exception as error:
            self._append_log(f"[local] Connection failed: {error}")
            self.client_socket = None
            return

        self._set_status(f"Connected to {host_value}:{port_value} as {self.user_name}")
        self._append_log("[local] Connected.")

        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

    def _receive_loop(self) -> None:
        assert self.client_socket is not None
        while True:
            try:
                incoming_bytes = self.client_socket.recv(4096)
                if not incoming_bytes:
                    raise ConnectionError("Disconnected.")
                incoming_text = incoming_bytes.decode(errors="replace")
            except Exception as error:
                self.incoming_queue.put(f"[local] Receive loop ended: {error}")
                break

            self.incoming_queue.put(incoming_text)

    def close_and_quit(self) -> None:
        if self.client_socket is not None:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        self.root.destroy()

    # Sending
    def _send_text(self, text_to_send: str) -> None:
        if self.client_socket is None:
            self._append_log("[local] Not connected.")
            return

        try:
            self.client_socket.sendall(text_to_send.encode())
        except Exception as error:
            self._append_log(f"[local] Send failed: {error}")

    def send_chat_message(self) -> None:
        raw_message = self.message_entry.get().strip()
        if not raw_message:
            return

        self.message_entry.delete(0, "end")

        timestamp_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        outgoing_line = f"[{timestamp_text}] {self.user_name}: {raw_message}"
        self._append_log(outgoing_line)
        self._send_text(outgoing_line)

    # Incoming handling
    def _handle_incoming_text(self, incoming_text: str) -> None:
        incoming_text = incoming_text.strip()
        if not incoming_text:
            return

        if incoming_text.startswith(CONTROL_PREFIX):
            self._handle_control_message(incoming_text)
        else:
            self._append_log(incoming_text)

    def _handle_control_message(self, control_text: str) -> None:
        # Format: CTRL|TYPE|SENDER|...
        parts = control_text.split("|")
        if len(parts) < 3:
            self._append_log("[local] Malformed control message.")
            return

        _, message_type, sender_name, *payload_parts = parts

        if sender_name == self.user_name:
            # If the server ever echoed back (it shouldn't with the relay code), ignore.
            return

        if message_type == "DH_PUB":
            self._handle_dh_public(sender_name, payload_parts)
            return

        if message_type == "RSA_PUB":
            self._handle_rsa_public(sender_name, payload_parts)
            return

        if message_type == "RSA_SECRET":
            self._handle_rsa_secret(sender_name, payload_parts)
            return

        self._append_log(f"[local] Unknown control type: {message_type}")


    # Diffie–Hellman
    def start_diffie_hellman(self) -> None:
        """
        Generates DH private/public and broadcasts our public value.
        When peer public arrives, compute shared secret.
        """
        if self.client_socket is None:
            self._append_log("[local] Connect first.")
            return

        # Private exponent: 256 bits is fine for a demo even with 2048-bit p.
        self.dh_private_exponent = random.getrandbits(256)
        self.dh_public_value = modular_exponentiation(DH_GENERATOR_G, self.dh_private_exponent, DH_PRIME_P)

        self.peer_dh_public_value = None
        self.dh_shared_secret = None

        self._append_log("[local] DH: Generated private exponent + public value. Sending DH public...")
        self._set_status("DH public sent. Waiting for peer DH public...")

        self._send_text(f"CTRL|DH_PUB|{self.user_name}|{self.dh_public_value}")

    def _handle_dh_public(self, sender_name: str, payload_parts: list[str]) -> None:
        if len(payload_parts) != 1:
            self._append_log("[local] DH_PUB payload malformed.")
            return

        try:
            peer_public = int(payload_parts[0])
        except ValueError:
            self._append_log("[local] DH_PUB payload not an integer.")
            return

        self.peer_dh_public_value = peer_public
        self._append_log(f"[local] DH: Received peer public from {sender_name}.")

        if self.dh_private_exponent is None:
            self._append_log("[local] DH: You have not generated your DH values yet. Click the DH button too.")
            self._set_status("DH peer public received. Generate your DH to compute secret.")
            return

        self.dh_shared_secret = modular_exponentiation(self.peer_dh_public_value, self.dh_private_exponent, DH_PRIME_P)

        # For display: show a short fingerprint rather than the huge number.
        fingerprint = self.dh_shared_secret % (10**12)
        self._append_log(f"[local] DH: Shared secret computed. Fingerprint (mod 1e12) = {fingerprint}")
        self._set_status("DH shared secret established.")


    # RSA shared secret
    def start_rsa_secret(self) -> None:
        """
        Initiator path:
          1) Ensure we have our RSA keys; broadcast our public key.
          2) If we already have peer public key, generate random secret and send encrypted secret.
          3) Otherwise wait until peer key arrives; then you can press again (or press once more after peer arrives).
        """
        if self.client_socket is None:
            self._append_log("[local] Connect first.")
            return

        if self.rsa_keys is None:
            self._append_log("[local] RSA: Generating RSA keypair (may take a moment)...")
            # 512-bit primes -> ~1024-bit modulus (reasonable for classroom demo speed).
            self.rsa_keys = generate_rsa_keypair(prime_bits=512)
            self._append_log("[local] RSA: Keypair generated.")

        # Always broadcast our public key when button pressed
        self._send_text(f"CTRL|RSA_PUB|{self.user_name}|{self.rsa_keys['public_e']}|{self.rsa_keys['public_n']}")
        self._append_log("[local] RSA: Public key sent. If peer key is known, will send encrypted secret.")

        if self.peer_rsa_public_e is None or self.peer_rsa_public_n is None:
            self._set_status("RSA public sent. Waiting for peer RSA public...")
            return

        # We are initiator: generate secret, encrypt with peer public key, send.
        # Keep secret smaller than n.
        secret_value = random.randrange(2, self.peer_rsa_public_n - 1)
        ciphertext_value = modular_exponentiation(secret_value, self.peer_rsa_public_e, self.peer_rsa_public_n)

        self.rsa_shared_secret = secret_value

        self._send_text(f"CTRL|RSA_SECRET|{self.user_name}|{ciphertext_value}")

        fingerprint = self.rsa_shared_secret % (10**12)
        self._append_log(f"[local] RSA: Shared secret generated + encrypted to peer. Fingerprint (mod 1e12) = {fingerprint}")
        self._set_status("RSA secret sent to peer (encrypted).")

    def _handle_rsa_public(self, sender_name: str, payload_parts: list[str]) -> None:
        if len(payload_parts) != 2:
            self._append_log("[local] RSA_PUB payload malformed.")
            return

        try:
            peer_e = int(payload_parts[0])
            peer_n = int(payload_parts[1])
        except ValueError:
            self._append_log("[local] RSA_PUB payload not integers.")
            return

        self.peer_rsa_public_e = peer_e
        self.peer_rsa_public_n = peer_n

        self._append_log(f"[local] RSA: Received peer public key from {sender_name}.")
        self._set_status("Peer RSA public received. Press RSA button to initiate secret (or re-initiate).")

    def _handle_rsa_secret(self, sender_name: str, payload_parts: list[str]) -> None:
        if len(payload_parts) != 1:
            self._append_log("[local] RSA_SECRET payload malformed.")
            return

        if self.rsa_keys is None:
            self._append_log("[local] RSA: You do not have an RSA keypair yet. Press RSA button to generate.")
            return

        try:
            ciphertext_value = int(payload_parts[0])
        except ValueError:
            self._append_log("[local] RSA_SECRET payload not an integer.")
            return

        # Receiver decrypts with private exponent d
        decrypted_secret = modular_exponentiation(ciphertext_value, self.rsa_keys["private_d"], self.rsa_keys["public_n"])
        self.rsa_shared_secret = decrypted_secret

        fingerprint = self.rsa_shared_secret % (10**12)
        self._append_log(f"[local] RSA: Encrypted secret received from {sender_name}. Decrypted. Fingerprint (mod 1e12) = {fingerprint}")
        self._set_status("RSA shared secret established (received & decrypted).")


    # Run
    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    application = TwoClientChatGui()
    application.run()
