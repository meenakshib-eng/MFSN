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
import sys
import argparse

# Additional import for experiments (user chose to keep pandas)
import pandas as pd

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
# Step 7: Plot Probability History
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
# Fernet parameter experiment (integrated)
# Usage: python main.py --fernet-exp [--fernet-kdf] [--fernet-trials N] [--fernet-out ./results]
# -----------------------
def run_fernet_parameter_experiments(cipher=None, use_kdf=False, kdf_iters_list=None,
                                     payload_sizes=None, items_per_batch_list=None,
                                     trials=5, out_dir=None):
    """
    Runs experiments varying payload size, batch size, and optional KDF iteration cost.
    - cipher: a cryptography.Fernet instance (if None, a fresh one is created)
    - use_kdf: if True, derive Fernet keys from a password with varying PBKDF2 iterations
    - kdf_iters_list: list of iteration counts to test (only used if use_kdf True)
    - payload_sizes: list of payload sizes in bytes to test
    - items_per_batch_list: list of batch sizes (how many separate payloads encrypted per measurement)
    - trials: repetitions per configuration
    - out_dir: where to save CSV and plots (defaults to script dir)
    Returns (pandas.DataFrame, csv_path)
    """
    import os, time, json, base64
    import numpy as np
    import matplotlib.pyplot as plt
    try:
        from cryptography.fernet import Fernet as _Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        raise RuntimeError("Required cryptography library not available: " + str(e))

    # sensible defaults (change these if you prefer other ranges)
    if payload_sizes is None:
        payload_sizes = [32, 128, 512, 2048, 8192, 32768]
    if items_per_batch_list is None:
        items_per_batch_list = [1, 10, 50, 200]
    if kdf_iters_list is None:
        kdf_iters_list = [1000, 5000, 20000]

    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(__file__) or os.getcwd(), PLOTS_DIR)
    os.makedirs(out_dir, exist_ok=True)

    def derive_fernet_key(password_bytes, salt, iterations):
        # derive 32 bytes and base64-url-safe encode to Fernet key
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                         iterations=iterations, backend=default_backend())
        key = kdf.derive(password_bytes)
        return base64.urlsafe_b64encode(key)

    # use provided cipher or a generated one (no KDF)
    base_cipher = cipher if cipher is not None else _Fernet(_Fernet.generate_key())

    rows = []
    salt = b'some_fixed_salt'  # fixed salt so KDF timing variation is dominated by iterations

    kdf_key_variants = kdf_iters_list if use_kdf else [None]

    for k_iter in kdf_key_variants:
        # pick cipher to use for this k_iter
        if k_iter is None:
            bench_cipher = base_cipher
            kdf_label = 'no_kdf'
        else:
            pwd = b'benchmark_password'
            derived_key = derive_fernet_key(pwd, salt, k_iter)
            bench_cipher = _Fernet(derived_key)
            kdf_label = f'kdf_{k_iter}'

        for payload_size in payload_sizes:
            # create one sample payload of given size (reuse for each trial to reduce allocation noise)
            payload = (b'A' * payload_size)

            for batch_size in items_per_batch_list:
                enc_times = []
                dec_times = []
                for _ in range(trials):
                    payloads = [payload for _ in range(batch_size)]
                    # encryption
                    t0 = time.perf_counter()
                    encrypted = [bench_cipher.encrypt(p) for p in payloads]
                    enc_elapsed = time.perf_counter() - t0
                    enc_times.append(enc_elapsed)
                    # decryption
                    t0 = time.perf_counter()
                    decrypted = [bench_cipher.decrypt(t) for t in encrypted]
                    dec_elapsed = time.perf_counter() - t0
                    dec_times.append(dec_elapsed)

                rows.append({
                    'kdf_variant': kdf_label,
                    'kdf_iters': (k_iter if k_iter is not None else 0),
                    'payload_size_bytes': payload_size,
                    'batch_size': batch_size,
                    'enc_mean_s': float(np.mean(enc_times)),
                    'enc_std_s': float(np.std(enc_times, ddof=1)) if len(enc_times) > 1 else 0.0,
                    'dec_mean_s': float(np.mean(dec_times)),
                    'dec_std_s': float(np.std(dec_times, ddof=1)) if len(dec_times) > 1 else 0.0,
                    'trials': trials
                })

    df = pd.DataFrame(rows)
    csv_path = os.path.join(out_dir, 'fernet_param_experiment_results.csv')
    df.to_csv(csv_path, index=False)

    # Generate plots per KDF variant
    for k_label, sub in df.groupby('kdf_variant'):
        plt.figure(figsize=(8,4))
        for batch, grp in sub.groupby('batch_size'):
            plt.plot(grp['payload_size_bytes'], grp['enc_mean_s'], marker='o', label=f'batch {batch}')
        plt.xscale('log')
        plt.yscale('log')
        plt.xlabel('Payload size (bytes) [log]')
        plt.ylabel('Encryption time (s) [log]')
        plt.title(f'Encrypt time vs payload size — {k_label}')
        plt.legend()
        plt.grid(True, which='both', ls='--', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f'enc_time_vs_payload_{k_label}.png'))
        plt.close()

        plt.figure(figsize=(8,4))
        for batch, grp in sub.groupby('batch_size'):
            plt.plot(grp['payload_size_bytes'], grp['dec_mean_s'], marker='o', label=f'batch {batch}')
        plt.xscale('log'); plt.yscale('log')
        plt.xlabel('Payload size (bytes) [log]')
        plt.ylabel('Decryption time (s) [log]')
        plt.title(f'Decrypt time vs payload size — {k_label}')
        plt.legend()
        plt.grid(True, which='both', ls='--', alpha=0.6)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f'dec_time_vs_payload_{k_label}.png'))
        plt.close()

    print(f'Fernet parameter experiments complete. CSV: {csv_path}')
    return df, csv_path


# -----------------------
# Main flow - adheres to requested order
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
    # Command-line quick hook: if user supplies --fernet-exp run the experiments and exit.
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--fernet-exp', action='store_true', help='Run integrated Fernet parameter experiments and exit')
    parser.add_argument('--fernet-kdf', action='store_true', help='Enable KDF timing (PBKDF2) in experiments')
    parser.add_argument('--fernet-trials', type=int, default=5, help='Number of trials per configuration')
    parser.add_argument('--fernet-out', type=str, default=None, help='Output directory for experiment CSV/PNGs')
    args, remaining = parser.parse_known_args()

    if args.fernet_exp:
        # try to reuse the program's cipher
        _cipher = globals().get('cipher', None)
        out_dir = args.fernet_out if args.fernet_out else PLOTS_DIR
        run_fernet_parameter_experiments(cipher=_cipher, use_kdf=args.fernet_kdf,
                                         trials=args.fernet_trials, out_dir=out_dir)
        sys.exit(0)

    # otherwise run normal program
    main()
