# Installation & Cross-Platform Guide

This guide provides deep, situation-aware setup instructions across **macOS (Apple Silicon & Intel)**, **Linux (Debian/Ubuntu, RHEL/Fedora, Arch)**, and **Windows (WSL2)**, as well as considerations for **arm64 vs. amd64** CPU architectures and hardware constraints.

---

## Hardware & Architecture Overview

`elyrn.` is engineered to be portable and lightweight:
- **Backend:** Go (the images and CI build with Go 1.27.4; `backend/go.mod` accepts 1.26 or newer) with one of two byte-for-byte equivalent crypto engines: OpenSSL 3.5 LTS through cgo (default, linked against Debian's `libssl3t64`) or the Go standard library (`ENGINE=native`, `CGO_ENABLED=0`, a static binary); the image builds a stripped, reproducible binary and runs it as an unprivileged user (uid 10001).
- **Frontend:** Vanilla modern JavaScript using the native W3C WebCrypto API (no webpack, no npm bundle dependencies for runtime).
- **Docker Images:** `golang:1.27.4-trixie` (build), `debian:trixie-slim`, `postgres:15-alpine` and `nginx:1.30-alpine` have official multi-architecture support for both `linux/amd64` and `linux/arm64`.

| Architecture | Platform Examples | Build Support | Performance Notes |
|---|---|---|---|
| **`amd64` (x86_64)** | Intel Core/Xeon, AMD Ryzen/EPYC | Native | Full AVX2 / SHA extensions acceleration |
| **`arm64` (aarch64)** | Apple Silicon (M1-M4), AWS Graviton, Raspberry Pi 4/5 | Native | Hardware accelerated SHA-256 and AES |

---

## macOS Installation (Apple Silicon & Intel)

### Prerequisites

Install Docker Desktop (or OrbStack / Colima) and, for running tests natively or building `elyrn-agent`, Go 1.26 or newer (1.27.4 recommended: it carries the security fixes the images use) and Node.js 20+ (`brew install go node`). The system `openssl` is enough for `make setup`: it calls `openssl rand`, which LibreSSL implements with the platform CSPRNG, and `make certs` (the database TLS certificates) uses only `ecparam`, `req` and `x509`, which LibreSSL and OpenSSL both provide.

Docker builds need nothing else: the OpenSSL engine compiles inside the image against Debian's OpenSSL 3.5 LTS. To run the **OpenSSL engine natively** (`make test-unit ENGINE=openssl`), install OpenSSL >= 3.2 development files and `pkg-config` (`brew install openssl@3 pkg-config`; Debian/Ubuntu: `apt install libssl-dev pkg-config`; on Ubuntu 22.04, whose OpenSSL is 3.0, use Docker or the native engine). The build stops with a clear error on older headers, and the binary refuses to start on an older runtime library.

### Docker Desktop on macOS
- Ensure Docker Desktop is running.
- **Apple Silicon Tip:** In Docker Desktop Settings -> *General*, ensure **"Use Rosetta for x86/amd64 emulation on Apple Silicon"** is enabled if cross-compiling, but for `elyrn.`, let Docker build natively for `linux/arm64` (fastest compilation and execution).

---

## Linux Installation (Debian, Ubuntu, RHEL, Fedora, Arch)

### 1. Ubuntu / Debian

```bash
# Update repositories
sudo apt-get update

# Install prerequisites
sudo apt-get install -y openssl curl git ca-certificates

# Install Docker Engine & Docker Compose Plugin
sudo apt-get install -y docker.io docker-compose-v2
```

### 2. Fedora / Red Hat / Rocky Linux

```bash
sudo dnf install -y openssl git curl make
sudo dnf install -y docker-ce docker-compose-plugin
sudo systemctl enable --now docker
```

### 3. Arch Linux

```bash
sudo pacman -Syu --needed openssl git docker docker-compose make
sudo systemctl enable --now docker
```

### Critical Linux Permission Check (Non-Root Docker)

If running `make up` fails with `permission denied while trying to connect to the Docker daemon socket`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply group changes immediately (or logout and log back in)
newgrp docker

# Verify docker runs without sudo
docker ps
```

---

## Windows 10 / 11 Installation (via WSL2)

`elyrn.` relies on a standard Makefile, Linux-targeted Docker images, and Unix socket conventions. **Running directly on native Windows PowerShell/CMD is not supported; you MUST use WSL2.**

### The CRLF vs. LF Line-Ending Trap

When Git clones a repository on Windows, it often automatically converts Unix line endings (`LF`) to Windows carriage returns (`CRLF`).
If shell scripts or Makefile recipes contain `\r`, commands may fail with errors such as:
```text
bash: \r: invalid command
```

### Complete Windows Setup Procedure

1. **Install WSL2 (if not already installed):**
   Open PowerShell as Administrator:
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
   Restart your PC if prompted.

2. **Configure Git in WSL2 to preserve Unix line endings:**
   Inside your WSL2 terminal:
   ```bash
   git config --global core.autocrlf input
   ```

3. **If you already cloned the repo and have CRLF errors:**
   Fix line endings with one command inside WSL:
   ```bash
   sudo apt-get install -y dos2unix
   dos2unix Makefile
   ```

4. **Install Docker Desktop for Windows:**
   - In Docker Desktop Settings -> *General*, check **"Use the WSL 2 based engine"**.
   - In Settings -> *Resources* -> *WSL Integration*, enable integration with your installed distribution (e.g., `Ubuntu-24.04`).

5. **Execute Setup and Launch inside WSL2:**
   ```bash
   make setup
   make up
   ```
   Access the app from your Windows browser at `http://localhost`.

---

## Development and Production Layouts

`make up` reads `APP_ENV` (the shell's value wins over `.env`). In `development`, the default,
it adds [docker-compose.dev.yaml](../../docker-compose.dev.yaml): the backend on
`127.0.0.1:8080` and PostgreSQL on `127.0.0.1:$DB_HOST_PORT` (TLS only) for debugging, `psql`
and host-side tools. In `production` only nginx is published. Every container runs restricted
either way; see [Container Hardening](../operations/hardening.md).

```bash
make up                         # layout from .env
APP_ENV=production make up      # production layout without editing .env
make check-hardening            # the rendered config keeps every container control
```

---

## Memory Sizing & VPS Optimization (Argon2id)

`elyrn.` runs memory-hard Argon2id on the server once per account, in registration phase 2, to hash the derived auth key (login proves the key by its keyed lookup and runs no Argon2id):
- **Default configuration:** `ARGON2_MEMORY_KIB=65536` (64 MiB per hash), `ARGON2_PARALLELISM=2` (`.env.example`; `4` when unset), at most `ARGON2_MAX_CONCURRENT=4` at once.
- **RAM Impact:** each concurrent registration phase 2 allocates `ARGON2_MEMORY_KIB`; the peak is `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB` (256 MiB with the defaults), which the backend container's 512 MiB limit (`BACKEND_MEM_LIMIT`) is sized for.

### Low-RAM Budget VPS Profile (512 MB - 1 GB RAM)

If deploying to a minimal VPS (e.g., a $4/month VPS with 1 GB RAM), concurrent registration spikes can trigger the Linux Out-Of-Memory (OOM) Killer.

Tune `.env` with these hardened low-memory parameters:

```ini
# Safe for 1GB RAM machines (prevents OOM crashes while maintaining high security)
ARGON2_MEMORY_KIB=32768
ARGON2_TIME=2
ARGON2_PARALLELISM=1
```

And add a 2GB swapfile on your Linux host:
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Local Host Development (Without Docker)

If you prefer running the Go server and tests natively on your host machine:

### 1. Go Toolchain
```bash
# Verify Go version >= 1.26 (1.27.4 recommended)
go version
```
Dependencies are managed via Go modules (`backend/go.mod`). Run:
```bash
cd backend
go mod download
```

### 2. Node.js (For the Frontend Tests)
Node.js 20+ has native support for `node:crypto` with WebCrypto X25519 and `node --test`:
```bash
node -v # Must be >= 20.0.0
node --test frontend/tests/*.test.mjs     # make test-crypto
```
No `package.json` or `npm install` is required; it executes against Node's built-in test runner.

---

### Next Steps:
- Read [**System Architecture**](../architecture/system-overview.md) to understand how data flows.
- Review [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md) if you encounter port conflicts or network issues.
