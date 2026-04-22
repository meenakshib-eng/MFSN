# Secure Encrypted Social Network Authentication System

A Python-based security simulation project that demonstrates **graph encryption, password authentication, probabilistic unlocking, and cryptographic performance benchmarking** in a social network environment.

This project simulates a **star topology social network**, where users must authenticate successfully to unlock an encrypted network.

---

## Project Overview

The system creates a secure network of users represented as graph nodes.

### Workflow:
1. Create a social network graph
2. Encrypt node identities and edges
3. Authenticate users using hashed passwords
4. Calculate unlock probability
5. Unlock network if authentication threshold is met
6. Benchmark encryption/decryption performance
7. Run Fernet parameter experiments

---

## Features

### 1. Social Network Graph
- Uses **NetworkX**
- Implements a **Star Topological Network**
- Central node connected to all other nodes

Example:

```text
        B
        |
C ---- A ---- D
        |
        E