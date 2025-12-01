# SoterG Stratum Proxy

A lightweight Stratum proxy for the **SoterG proof‑of‑work algorithm**.  
This proxy bridges standard mining software with the Soteria node RPC, so miners can connect using Stratum instead of direct RPC calls.

Unlike Kawpow proxies, this implementation supports **SoterG**, which derives its hash rotation order from the block timestamp masked with `TIME_MASK = 0xFFFFFFA0`.

---

## ✨ Features
- Full Stratum server for miners (`mining.subscribe`, `mining.authorize`, `mining.notify`, `mining.submit`).
- Builds block templates from your Soteria node (`getblocktemplate`).
- Constructs coinbase transactions with deterministic miner/foundation reserve split.
- Computes merkle roots and block headers.
- Sends miners explicit **SoterG rotation metadata**:
  - `selector_le`: SHA256d(nTime & TIME_MASK), little‑endian
  - `rotations`: 12 algorithm indices (0–11) chosen per `GetHashSelection`
  - `header_le`: 80‑byte block header (without nonce)
- Compatible with testnet and mainnet.
- Simple Python 3 asyncio implementation.

---

## ⚙️ Requirements

### Windows (batch file)

## 🪟 Windows Quick Start

1. **Double‑click `stratum.bat`.**  
   - This script will download Python (if needed), install pip, install all required modules, and then ask you for your node details (IP, RPC port, username, password, etc.).  
   - It will also ask which port you want miners to connect to (the Stratum port).  
   - Finally, it will generate a launcher file called `stratum.bat` in the **main proxy folder**.  

2. **Start the proxy:**  
   - After setup, go to the main proxy folder (where `soterg-stratum-proxy.py` is).  
   - Double‑click the newly generated `stratum.bat`.  
   - You’ll see a message like:  
     ```
     Connect to your stratum proxy at stratum+tcp://localhost:3333
     ```
     (replace `3333` with the port you chose).  

3. **Point your miner to the proxy:**  
   - Example miner URL:  
     ```
     stratum+tcp://127.0.0.1:3333
     ```
   - Use your chosen username/password when configuring the miner.

#### Note : The first run of stratum.bat is setup, and the second run of stratum.bat (generated in the main folder) is the actual launcher.
---

#### Linux/macOS users should run the pip command manually.
 
- Python 3.9+
- Dependencies:
  ```bash
  pip install aiohttp aiorpcx base58
  ```
  (or use `apt install python3-aiohttp python3-aiorpcx python3-base58` on Debian/Ubuntu)

### 🔹 Option 1: Use distro packages
On Debian/Ubuntu, many Python libraries are packaged.
```bash
sudo apt update
sudo apt install python3-aiohttp python3-aiorpcx python3-base58
```
That installs them system‑wide in the managed environment.

---

### 🔹 Option 2: Create a virtual environment
This is the most flexible way to run stratum proxy without touching system Python:

```bash
# Make sure you have python3-full installed
sudo apt install python3-full python3-venv

# Create a new virtual environment
python3 -m venv ~/soterg-stratum-proxy-venv

# Activate it
source ~/soterg-stratum-proxy-venv/bin/activate

# Now pip works inside the venv
pip install aiohttp aiorpcx base58
```

Every time you want to run the stratum proxy, activate the venv first:
```bash
source ~/soter-proxy-venv/bin/activate
python soterg-stratum-proxy.py ...
```
---

### 🔹 Option 3: Use pipx
`pipx` manages isolated environments for apps:
```bash
sudo apt install pipx
pipx install aiohttp aiorpcx base58
```
This is good if you want to run the stratum proxy as a standalone tool.

---

### 🔹 Option 4: Make sure Python 3.9+ is installed:
   ```bash
   python3 --version
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   > `requirements.txt` includes:
   > ```
   > aiohttp
   > aiorpcx
   > base58
   > pysha3
   > ```

### ⚠️ Avoid `--break-system-packages`
You *can* override with `pip install --break-system-packages ...`, but that risks breaking your distro’s Python. Safer to use apt or a venv.

---

👉 For stratum proxy, We recommend **Option 2 (venv)**: it keeps dependencies clean, lets you upgrade freely, and won’t interfere with system Python.  

---

## 🚀 Usage

Run the stratum proxy with:

```bash
python3 soterg-stratum-proxy.py proxy_port node_ip node_username node_password node_port listen_externally [testnet]
```

### Arguments
- `proxy_port` → Port miners connect to (e.g. `3333`)
- `node_ip` → IP of your Soteria node (e.g. `127.0.0.1`)
- `node_username` → RPC username
- `node_password` → RPC password
- `node_port` → RPC port your node listens on
- `listen_externally` → `true` to bind to all interfaces, `false` for localhost only
- `testnet` (optional) → `true` if running on testnet, `false` otherwise
NOTE: the proxy doesn’t care what the port number is, as long as it matches node’s RPC port.

### Example
```bash
python3 soterg-stratum-proxy.py 3333 127.0.0.1 rpcuser rpcpass <your_rpc_port> false true
```
### Example miner connection
Point your miner to:
```
stratum+tcp://127.0.0.1:3333
```
using your chosen username/password.

---

## Video Instruction:

#### For Windows
https://www.youtube.com/watch?v=AOMUkxFzb8U

#### For Linux
https://www.youtube.com/watch?v=f6RqfnguN0Q


## 🔑 How x12rt Rotation Works

SoterG uses a **12‑hash rotation** chosen from:
```
0: blake512
1: shabal512
2: groestl512
3: jh512
4: sha3_512
5: skein512
6: luffa512
7: cubehash512
8: simd512
9: echo512
10: hamsi512
11: sha512
```

The order is determined by:
1. Masking the block timestamp:  
   ```
   nTimeSoterG = nTime & 0xFFFFFFA0
   ```
2. Hashing that masked time with SHA256d → `selector_le`.
3. For each round `i = 0..11`, calling `GetHashSelection(selector_le, i)` to pick the algorithm.
4. Miners receive the 12 rotations in `mining.notify` and apply them to the block header + nonce.

This ensures consensus between node and miners.

---

## 🧪 Testing
- Run with dummy RPC credentials to check syntax and startup.
- With a live node, you should see:
  - `New block, update state`
  - `mining.notify` messages sent to miners
- Miners should report hashrate and submit shares via the proxy.

---

## 🤝 Contributing
This stratum proxy is open‑source and intended for community use.  

---

## 📄 License
MIT License — free to use, modify, and share.
```
