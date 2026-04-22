import networkx as nx
import matplotlib.pyplot as plt
from cryptography.fernet import Fernet
import bcrypt
import json
import os
import math
import numpy as np
import time
from statistics import mean

# -----------------------
# Configuration
# -----------------------
PASSWORD_FILE = "hashed_passwords.json"
PLOTS_DIR = "plots"
BENCH_ITER = 500  # number of iterations for timing benchmark

# -----------------------
# Helpers
# -----------------------

def ensure_plots_dir():
    if not os.path.exists(PLOTS_DIR):
        os.makedirs(PLOTS_DIR)


# -----------------------
# Step 0: Define Friends (Star Network)
# -----------------------
friends = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']
central_node = 'A'  # A is the central friend

# Create star edges (A connected to everyone else)
edges = [(central_node, f) for f in friends if f != central_node]

# -----------------------
# Step 1: Checks / Setup Passwords
# -----------------------

def setup_or_load_passwords():
    # If password file does not exist, create one interactively.
    if not os.path.exists(PASSWORD_FILE):
        print("🔐 Password file not found. Setting up passwords for all users (only once)...")
        hashed_passwords = {}
        for f in friends:
            pw = input(f"Set password for {f}: ")
            hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
            hashed_passwords[f] = hashed
        with open(PASSWORD_FILE, "w") as fh:
            json.dump(hashed_passwords, fh)
        print("\n✅ Passwords saved securely in 'hashed_passwords.json'\n")
    else:
        with open(PASSWORD_FILE, "r") as fh:
            hashed_passwords = json.load(fh)
        print(f"🔎 Password file found and loaded ({len(hashed_passwords)} users).")
    return hashed_passwords


# -----------------------
# Step 2: Setup Encryption
# -----------------------

# Generate a key/cipher for this run (in a real system you'd persist the key)
key = Fernet.generate_key()
cipher = Fernet(key)


# -----------------------
# Step 3: Encrypt Node Names and Edges (for locked view)
# -----------------------

def encrypt_graph_data():
    encrypted_nodes = {f: cipher.encrypt(f.encode()).decode() for f in friends}
    encrypted_edges = [(cipher.encrypt(a.encode()).decode(),
                        cipher.encrypt(b.encode()).decode()) for a, b in edges]
    return encrypted_nodes, encrypted_edges


# -----------------------
# Step 4: Show Locked Graph
# -----------------------

def show_locked_graph(encrypted_nodes, encrypted_edges, save=True):
    G = nx.Graph()
    G.add_nodes_from(encrypted_nodes.values())
    G.add_edges_from(encrypted_edges)

    plt.figure(figsize=(7, 6))
    nx.draw(G, with_labels=True, node_color='salmon', node_size=2200,
            font_size=8, font_weight='bold')
    plt.title("🔒 Encrypted Star Network (Locked)")
    if save:
        path = os.path.join(PLOTS_DIR, "locked_network.png")
        plt.tight_layout()
        plt.savefig(path)
        print(f"📁 Saved locked graph to: {path}")
    plt.show()


# -----------------------
# Step 5: Authentication
# -----------------------

probability_history = []
attempt_labels = []


def authenticate_all_users(hashed_passwords):
    authenticated_users = []
    print("\n🔐 Secure Star Network Authentication 🔐")
    print("------------------------------------------")

    for friend in friends:
        entered_pw = input(f"Enter password for {friend}: ")
        try:
            ok = bcrypt.checkpw(entered_pw.encode(), hashed_passwords[friend].encode())
        except Exception:
            ok = False
        if ok:
            print(f"✅ {friend} authenticated successfully.")
            authenticated_users.append(friend)
        else:
            print(f"❌ Authentication failed for {friend}.")
    return authenticated_users


# -----------------------
# Step 6: Decryption / Unlock
# -----------------------

def unlock_network(encrypted_edges, authenticated_users, attempt_no=1):
    total = len(friends)
    success = len(authenticated_users)

    P_unlock = success / total
    probability_history.append(P_unlock)
    attempt_labels.append(f"Attempt {attempt_no}")

    print(f"\n🔢 Conditional Probability of Unlock = {P_unlock:.2f}")

    # Requirement: At least 80% authenticated
    if P_unlock >= 0.8:
        print("🎯 Probability threshold met! Unlocking network (no random roll).")

        decrypted_graph = nx.Graph()
        for (ea, eb) in encrypted_edges:
            a = cipher.decrypt(ea.encode()).decode()
            b = cipher.decrypt(eb.encode()).decode()
            decrypted_graph.add_edge(a, b)

        plt.figure(figsize=(7, 6))
        nx.draw(decrypted_graph, with_labels=True, node_color='lightblue',
                node_size=2200, font_size=12, font_weight='bold')
        plt.title("🔓 Star Social Network (Unlocked)")
        path = os.path.join(PLOTS_DIR, "unlocked_network.png")
        plt.tight_layout()
        plt.savefig(path)
        print(f"📁 Saved unlocked graph to: {path}")
        plt.show()
    else:
        print("\n❌ Probability too low. Not enough users authenticated.")
        print(f"➡ Need at least {int(math.ceil(0.8 * total))} users authenticated to unlock.")


# -----------------------
# Step 7: Plot Probability Graph
# -----------------------

def plot_probability_history(save=True):
    if not probability_history:
        print("No probability history to plot.")
        return

    x = np.arange(1, len(probability_history) + 1)
    p = np.array(probability_history, dtype=float)

    plt.figure(figsize=(9, 4))
    plt.plot(x, p, marker='o', label='P_unlock (success/total)', linewidth=2)

    plt.title("Probability of Unlock per Attempt (No Random Roll)")
    plt.xlabel("Attempt Number")
    plt.xticks(x, attempt_labels, rotation=45)
    plt.ylabel("Value (0 to 1)")
    plt.ylim(0, 1.05)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    if save:
        path = os.path.join(PLOTS_DIR, "probability_history.png")
        plt.savefig(path)
        print(f"📁 Saved probability history plot to: {path}")
    plt.show()


# -----------------------
# Step 8: Benchmark Encryption/Decryption Timing and Save
# -----------------------

def benchmark_encrypt_decrypt(bench_iter=BENCH_ITER, save=True):
    # We'll time encrypting all node names and then decrypting them repeatedly
    encrypt_times = []
    decrypt_times = []

    # Warm-up
    for _ in range(10):
        for f in friends:
            _ = cipher.encrypt(f.encode())

    for i in range(bench_iter):
        # encrypt timing
        t0 = time.perf_counter()
        encs = [cipher.encrypt(f.encode()) for f in friends]
        t1 = time.perf_counter()
        encrypt_times.append(t1 - t0)

        # decrypt timing
        t0 = time.perf_counter()
        decs = [cipher.decrypt(e).decode() for e in encs]
        t1 = time.perf_counter()
        decrypt_times.append(t1 - t0)

    enc_mean = mean(encrypt_times)
    dec_mean = mean(decrypt_times)

    print(f"\n⚙️  Encryption benchmark (avg over {bench_iter} runs): {enc_mean:.6f} s")
    print(f"⚙️  Decryption benchmark (avg over {bench_iter} runs): {dec_mean:.6f} s")

    if save:
        # Save to JSON and plot a simple summary bar chart
        out = {
            'encrypt_mean_s': enc_mean,
            'decrypt_mean_s': dec_mean,
            'encrypt_times_s': encrypt_times,
            'decrypt_times_s': decrypt_times,
            'iterations': bench_iter,
        }
        json_path = os.path.join(PLOTS_DIR, "benchmark_results.json")
        with open(json_path, 'w') as fh:
            json.dump(out, fh)
        print(f"📁 Saved benchmark results to: {json_path}")

        # Plot
        plt.figure(figsize=(6, 4))
        plt.bar(['encrypt', 'decrypt'], [enc_mean, dec_mean])
        plt.ylabel('Average time (s)')
        plt.title('Encryption / Decryption Timing (avg)')
        plt.tight_layout()
        png_path = os.path.join(PLOTS_DIR, "benchmark_summary.png")
        plt.savefig(png_path)
        print(f"📁 Saved benchmark plot to: {png_path}")
        plt.show()

    return enc_mean, dec_mean


# -----------------------
# Main flow - adhers to requested order
# -----------------------

def main():
    ensure_plots_dir()

    # 1) checks the passwords
    hashed_passwords = setup_or_load_passwords()

    # 2) shows the locked graph
    encrypted_nodes, encrypted_edges = encrypt_graph_data()
    show_locked_graph(encrypted_nodes, encrypted_edges, save=True)

    # 3) authentication
    authenticated_users = authenticate_all_users(hashed_passwords)

    # 4) decryption
    unlock_network(encrypted_edges, authenticated_users, attempt_no=1)

    # 5) shows the unlocked graph (handled/ saved inside unlock_network)

    # 6) plots the graph (probability history)
    plot_probability_history(save=True)

    # 7) benchmarks the Encryption / decryption timing benchmark and saves to plots
    benchmark_encrypt_decrypt(bench_iter=BENCH_ITER, save=True)


if __name__ == '__main__':
    main()
