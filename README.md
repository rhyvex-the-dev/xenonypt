# Xenonypt 🔐

**Xenonypt** is a high-security, cross-platform encrypted file vault application built with **Flutter** and **Rust**. It provides military-grade file encryption, obfuscated storage, and hardware-bound biometric authentication to safeguard your sensitive files.

---

## ✨ Features

- 🛡️ **Rust Cryptography Core**: Powered by high-performance Rust (`vault.rs`) integrated via `flutter_rust_bridge` v2.
- 🔑 **Hardware-Bound Biometric Auth**: Integrates with Android Keystore (`setUserAuthenticationRequired`) and iOS Keychain (`biometryCurrentSet`) using non-exportable hardware keys.
- 🕵️ **Anonymous Storage & Obfuscation**: Vault folders and contained files use random 16-byte hex identifiers without identifiable extensions.
- 🎨 **Sleek Cyber UI**: Modern dark-mode Material 3 user interface with high-refresh-rate display support on Android.
- 📁 **File Management**: Securely import, view, extract, and purge encrypted files or loose files.
- 📱 **Cross-Platform**: Designed for Android, iOS, Windows, macOS, and Linux.

---

## 🛠️ Architecture

```
xenonypt/
├── lib/
│   ├── main.dart             # Flutter UI & Biometric Auth Handler
│   └── src/
│       ├── api.rs            # Rust API interface for flutter_rust_bridge
│       ├── vault.rs          # Encrypted Vault logic & file operations
│       └── rust/             # Generated FRB bindings
├── rust_builder/             # CargoKit integration for Flutter
└── pubspec.yaml              # Project dependencies & configurations
```

---

## 🚀 Getting Started

### Prerequisites

- [Flutter SDK](https://flutter.dev/docs/get-started/install) (v3.3.0 or higher)
- [Rust Toolchain](https://www.rust-lang.org/tools/install) (`cargo`, `rustc`)
- [flutter_rust_bridge_codegen](https://pub.dev/packages/flutter_rust_bridge) (v2.12.0)

### Installation & Running

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rhyvex-the-dev/xenonypt.git
   cd xenonypt
   ```

2. **Fetch dependencies:**
   ```bash
   flutter pub get
   ```

3. **Generate Rust-Dart bindings (if modifying Rust core):**
   ```bash
   flutter_rust_bridge_codegen generate
   ```

4. **Run the application:**
   ```bash
   flutter run
   ```

---

## 🔒 Security Highlights

- **Zero-Cache Biometrics**: Every unlock attempt invokes a fresh OS-level biometric prompt without persistent memory caching.
- **Hardware Sealing**: Keys are tied to the device's Secure Enclave / TEE; copying vault data to another device renders it unreadable without the original master passphrase.

---

## 📄 License

This project is open-source. See the repository details for licensing info.

