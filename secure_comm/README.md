# Secure Communication Prototype 🔐

**Description:**  
This is a research-grade, encrypted messaging prototype inspired by defence communication systems.  
It implements:

- End-to-End Encryption (AES-256-GCM)  
- RSA-4096 key exchange  
- Self-Destruct messages on retrieval  
- LAN mode ready  

**Use Case:**  
This project is developed for educational and research purposes in secure communication, inspired by systems used in Indian Army / DRDO / NTRO.

**Important Notes:**  
- This is a research prototype, not an operational Army/DRDO/NTRO system.  
- Do NOT share or store real sensitive information using this tool.  
- Private keys are excluded from the repository for security.

**Setup:**  
1. Clone repo  
2. Install dependencies: `pip install -r requirements.txt`  
3. Run server: `python3 server.py`  
4. Run client: `python3 client.py`  
5. Register users, send/receive encrypted messages  

**Files:**  
- `crypto_utils.py` → Crypto functions (AES, RSA)  
- `server.py` → Flask server for message relay  
- `client.py` → CLI client  
- `keys/` → Local folder to store keys (excluded from repo)
