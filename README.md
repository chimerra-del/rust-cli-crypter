## ⚠️ **IMPORTANT DISCLAIMER**
All ciphers, hash functions, and block modes in this repository have been **implemented manually from scratch** based on official NIST and RFC specifications without relying on high-level external cryptographic libraries. This software is **NOT intended for production use or real-world data protection**. Due to its experimental nature, edge-case bugs, runtime crashes, or susceptibility to side-channel attacks may exist. Use strictly for academic study, security auditing, and educational demonstrations!

## 🚀 Key Features

- **12 Symmetric Ciphers**: Ranging from historical primitives (Lucifer, Madryga, Vigenère) to modern standards (AES, ChaCha20, Camellia, RC5, XTEA).
- **6 Block Cipher Modes**: Native support for configurable operational modes (ECB, CBC, CFB, CTR, CCM, GCM).
- **Flexible Combinatorics**: Dynamic pairing of any supported block cipher with any mode of operation directly via terminal flags.
- **Hashing & KDF**: Custom hash functions (MurmurHash3, FNV1a, DJB2, SHA128) and key derivation routines (HKDF).
- **Binary Obfuscation**: Low-level data transformation modules for binary structure obfuscation.
- **Pure Rust Cryptographic Core**: Zero black-box crypto dependencies.

## Examples of usage
# AES-CBC
./rust-cli-crypter -p test.txt -a aes -f encrypt -k 0123456789abcdef0123456789abcdef -m cbc --iv 0123456789abcdef0123456789abcdef

# AES-GCM (с nonce)
./rust-cli-crypter -p test.txt -a aes -f encrypt -k 0123456789abcdef0123456789abcdef -m gcm --nonce 0123456789abcdef

# AES-CTR
./rust-cli-crypter -p test.txt -a aes -f encrypt -k 0123456789abcdef0123456789abcdef -m ctr --iv 0123456789abcdef


## 🔨 Architecture 
rust-cli-crypter/
├── Cargo.toml
├── Cargo.lock
└── src/
    ├── alg/                  # Cipher primitives (AES, ChaCha20, Camellia, Lucifer, etc.)
    ├── modes/                # Block modes of operation (ECB, CBC, CTR, GCM, etc.)
    ├── hashing/              # Hashing algorithms (FNV1a, MurmurHash3, DJB2, SHA128)
    ├── passwd_hashing/       # Key derivation & pseudorandom functions (HKDF)
    ├── obfuse/               # Binary transformation and obfuscation routines
    ├── cipher_factory.rs     # Factory pattern for dynamic Cipher + Mode assembly
    ├── cipher_modes.rs       # Mode abstractions & traits
    ├── rsp_parser.rs         # Response/Request vector parsing utilities
    └── main.rs               # CLI argument parsing and execution orchestration

## 🏫 Building 
# Clone the repository
git clone https://github.com/your-username/rust-cli-crypter.git
cd rust-cli-crypter

# Build in release mode
cargo build --release

# View command-line help
./target/release/rust-cli-crypter --help


## 🎓 Academic & Engineering Context

This project serves as a comprehensive demonstration of low-level systems programming, cryptography fundamentals, and software architecture principles in Rust:
1. **Cryptographic Foundations**: Hands-on implementation of Substitution-Permutation Networks (SPN), Feistel structures, and finite field arithmetic (Galois Fields).
2. **Design Patterns**: Utilization of the *Factory* and *Strategy* design patterns in Rust to achieve runtime decoupling between cipher primitives and operational block modes.
3. **Memory & Performance**: Explores safe low-level memory layout control, bitwise manipulations, and zero-allocation pipelines where possible.
