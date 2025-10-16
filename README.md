## 📡 **LoRaCrypt-MC**

**LoRa Crypt Multi Client — Secure multi-client LoRa + UART communication with libsodium encryption**

---

### 🧩 Project Overview

**LoRaCrypt-MC** implements a **multi-client LoRa communication system** with an **encryption layer based on [libsodium](https://doc.libsodium.org/)**.  
It enables secure data transmission between a server and multiple clients connected over **UART**, using both **symmetric and asymmetric encryption**, and a simple **user authentication system**.

The system operates in two modes:
- 🖥️ **Server (`-s`)** — manages connected clients, performs key exchange (handshake), handles logins, and processes commands.  
- 📱 **Client (`-c`)** — connects to the server, performs handshake, logs in, and securely exchanges encrypted messages.

---

### 🔐 Security Features

The project uses cryptographic primitives from **libsodium**:
- `crypto_kx_*` – for key pair and session key generation (RX/TX)  
- `crypto_secretbox_easy()` – for authenticated symmetric encryption  
- Unique **nonce (24 bytes)** for each message  
- **Public key handshake** between peers  
- **Encrypted login** based on a `users.json` file  

---

### 🧠 Architecture

#### Communication flow
```
[Client] <--UART/LoRa--> [Server]
   |                          |
 handshake + key exchange     |
   |------------------------->|
   |<-------------------------|
 authenticated encrypted chat |
```

#### Login sequence
1. After completing the session key exchange, the client sends an encrypted `LOGIN <username> <password>` message.  
2. The server validates the credentials from `users.json` and responds with:  
   - `LOGIN OK` → user authenticated  
   - `LOGIN FAIL` → invalid credentials  
   - `LOGIN REQUIRED` → login required before sending messages  

---

### 🧾 Example `users.json`
```json
[
  { "login": "admin", "password": "1234" },
  { "login": "user", "password": "test" }
]
```

---

### ⚙️ Compilation

Requirements:
- Linux or macOS  
- Installed **libsodium** library  
- GCC compiler  

Compile:
```bash
gcc loracrypt_mc.c -o loracrypt-mc -lsodium
```

---

### 🚀 Running

#### Server mode:
```bash
./loracrypt-mc -s /dev/ttyUSB0
```

#### Client mode:
```bash
./loracrypt-mc -c /dev/ttyUSB0
```

---

### 💬 Server Interactive Commands

| Command | Description |
|----------|-------------|
| `/list` | Lists all currently connected clients |
| `/send <idx> <text>` | Sends an encrypted message to a selected client |
| `/sendall <text>` | Sends a message to all connected clients |
| `<text>` | Sends message to client with index 0 (default) |

---

### 🔧 Data Structures

```c
typedef struct {
    unsigned char pk[PK_LEN];
    unsigned char rx_key[SESSION_KEY_LEN];
    unsigned char tx_key[SESSION_KEY_LEN];
    int logged_in;
    char username[64];
} client_t;
```

---

### 🔄 Handshake Process

1. Client sends a `0xFFFF` header, a “HELLO test123” message, and its **public key**.  
2. Server replies with its **public key**.  
3. Both sides compute shared **RX/TX session keys**.  
4. Secure login and encrypted communication become available.

---

### 🧰 Example Console Output

**Server:**
```
*** RUNNING AS SERVER ***
Server PK: 7f23a8...
New client added idx=0 pk=aa12ff...
Client 0 logged in as admin
User admin (idx=0): Hello world
```

**Client:**
```
*** RUNNING AS CLIENT ***
Sent handshake (HELLO + client PK) to server
Received server PK
Session keys computed (client)
Login: admin
Password: 1234
✅ Login successful!
Sent encrypted: Hello world
[Decrypted] Message received!
```

---

### ⚡ Key Features

- Multi-client support on a single server  
- Simple JSON-based user authentication (`users.json`)  
- Secure end-to-end encryption using libsodium  
- Works over **UART**, suitable for **LoRa modules** (DX-LR01, RFM95, SX127x, etc.)  
- Implemented in **pure ANSI C** with minimal dependencies  