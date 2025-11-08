# OC2 Save Batch Tool

A Python tool that automates **decryption and encryption** of multiple Overcooked All You Can Eat save files.  
This tool mainly focus to change the save file from 1 steam id account to another. 

---

## 🚀 Features

- 🔐 **Decrypt** multiple `.save` files into readable `.json` format  
- 🔄 **Encrypt** modified `.json` files back into `.save` format  
- 🗑️ Automatically cleans up temporary `.json` files after encryption

---

## 🖥️ How to Use
1. **Install requirements**
 ```bash
 pip install -r requirements.txt
 ```
2. **Run the batch tool**
  ```bash
  python oc2_batch_tool.py
  ```
When prompted:

Enter your SteamID64 for decryption (Owner of the save file)

Enter your SteamID64 for encryption (Your Steam ID)

The script will decrypt all .save files → create .json → re-encrypt them → remove .json files automatically.

