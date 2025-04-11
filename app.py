import streamlit as st
import hashlib
import json
import os
import uuid
from cryptography.fernet import Fernet

# --- Constants ---
DATA_FILE = "data.json"
ADMIN_PASSWORD = "admin123"

# --- Load or initialize data file ---
def load_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump({}, f)
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# --- Generate key and Fernet instance ---
if 'FERNET_KEY' not in st.session_state:
    st.session_state.FERNET_KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.FERNET_KEY)

# --- Session states ---
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# --- Utility functions ---
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

# --- Streamlit UI ---
st.title("🛡️ Advanced Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Load stored data from file
data_store = load_data()

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This is an advanced secure app using encryption, file storage, and passkey-based retrieval.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter the data to store:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_key = hash_passkey(passkey)
            uid = str(uuid.uuid4())
            data_store[uid] = {"encrypted_text": encrypted_text, "passkey": hashed_key}
            save_data(data_store)
            st.success("✅ Data encrypted and saved successfully!")
        else:
            st.error("⚠️ Please provide both data and a passkey.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔒 Access locked due to failed attempts. Please login.")
    else:
        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Paste encrypted data here:")
        passkey_input = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            found = False
            for item in data_store.values():
                if item["encrypted_text"] == encrypted_input:
                    found = True
                    if item["passkey"] == hash_passkey(passkey_input):
                        decrypted = decrypt_data(encrypted_input)
                        st.success(f"✅ Decrypted Data: {decrypted}")
                        st.session_state.failed_attempts = 0
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Wrong passkey! Attempts left: {remaining}")
                        if st.session_state.failed_attempts >= 3:
                            st.session_state.authorized = False
                            st.experimental_rerun()
                    break
            if not found:
                st.error("🔍 Encrypted data not found in storage.")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔐 Admin Login")
    login_input = st.text_input("Enter admin password:", type="password")

    if st.button("Login"):
        if login_input == ADMIN_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful. You can now retrieve data.")
        else:
            st.error("❌ Incorrect admin password.")
