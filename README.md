# 🔐 CN Secure File Transfer

This project is a **Computer Networks (CN)** course project that implements **secure file transfer** from one machine to another over a network using **AES encryption**.

It uses a **client-server model**, with:
- `final_sender.py`: the client script (sender)
- `final_rec.py`: the server script (receiver)

## ✨ Features

- 📡 **Port-to-port transfer** over TCP sockets
- 🔐 **AES encryption (EAX mode)** for confidentiality
- 🧂 **PBKDF2-based key derivation** using user passwords and random salts
- 🧾 **File metadata exchange** (filename, size)
- 📥 Real-time progress bar via `tqdm`
- ✅ Basic authentication before receiving files
- 📁 Save received files with custom directory options

## 📂 Project Structure
```
.
├── final_sender.py
├── final_rec.py
└── (other files)
```

## ⚙️ Requirements

Install dependencies using:

```bash
pip install pycryptodome tqdm
```

## 🚀 Usage

1. **Start the Receiver**  
   On the receiving machine:  
   ```bash
   python final_rec.py
   ```  
   Enter the preset code: `CN_SECURE_1234`  
   Choose IP address, port (default: 9999), and destination folder.

2. **Start the Sender**  
   On the sending machine:  
   ```bash
   python final_sender.py
   ```  
   Provide receiver’s IP and port.  
   Choose a file to send.  
   Enter a unique password for each file (used for encryption).

🔁 You can send/receive multiple files in a session.

## 🔒 Security Details

- AES EAX mode ensures both encryption and authentication.
- Random salt & nonce are used per file for added security.
- PBKDF2 ensures strong key derivation from weak user passwords.

## 📌 Notes

Make sure sender and receiver machines are on the same network or connected via port forwarding.  
The receiver must enter the same password used by the sender to successfully decrypt the file.
