# Encryption Simulator using Streamlit

import streamlit as st
import hashlib
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# ---------------- Encryption Functions ---------------- #
def xor_cipher(text, key):
    return ''.join(chr(ord(c) ^ ord(key)) for c in text)

def hash_text(text, method):
    if method == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif method == "SHA-1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif method == "SHA-256":
        return hashlib.sha256(text.encode()).hexdigest()
    return "Unsupported"

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def aes_encrypt(text, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text).encode())).decode()

def aes_decrypt(cipher_text, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(base64.b64decode(cipher_text)).decode().strip()

def des_encrypt(text, key):
    key = key[:8].ljust(8).encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text).encode())).decode()

def des_decrypt(cipher_text, key):
    key = key[:8].ljust(8).encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(base64.b64decode(cipher_text)).decode().strip()

# RSA key pair (small for demo purposes)
rsa_key = RSA.generate(2048)
rsa_pub_key = rsa_key.publickey()


def rsa_encrypt(text):
    cipher = PKCS1_OAEP.new(rsa_pub_key)
    return base64.b64encode(cipher.encrypt(text.encode())).decode()

def rsa_decrypt(cipher_text):
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(cipher_text)).decode()

# ---------------- Streamlit App ---------------- #
st.set_page_config(page_title="Encryption Simulator", layout="wide")
st.title("🔐 Encryption Simulator")

method = st.sidebar.selectbox("Choose Encryption Method", [
    "Caesar Cipher",
    "XOR Cipher",
    "Hashing Algorithms",
    "AES",
    "DES",
    "RSA"
])

# -------------- Caesar Cipher -------------- #
if method == "Caesar Cipher":
    st.subheader("Caesar Cipher")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
    text = st.text_area("Enter text")
    shift = st.slider("Shift", 1, 25, 3)
    if st.button("Run Caesar Cipher"):
        def caesar(text, shift):
            result = ""
            for c in text:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    result += chr((ord(c) - base + shift) % 26 + base)
                else:
                    result += c
            return result
        shift = shift if mode == "Encrypt" else -shift
        st.code(caesar(text, shift))

# -------------- XOR Cipher -------------- #
elif method == "XOR Cipher":
    st.subheader("XOR Cipher")
    text = st.text_area("Enter text")
    key = st.text_input("Enter key (1 character)")
    if st.button("Run XOR Cipher"):
        if len(key) == 1:
            st.code(xor_cipher(text, key))
        else:
            st.warning("Key must be a single character.")

# -------------- Hashing Algorithms -------------- #
elif method == "Hashing Algorithms":
    st.subheader("Hashing Algorithms")
    text = st.text_input("Enter text to hash")
    algo = st.selectbox("Choose hash algorithm", ["MD5", "SHA-1", "SHA-256"])
    if st.button("Hash Text"):
        st.code(hash_text(text, algo))

# -------------- AES Encryption -------------- #
elif method == "AES":
    st.subheader("AES Encryption")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
    text = st.text_area("Enter text")
    key = st.text_input("Enter key (any length)")
    if st.button("Run AES"):
        try:
            if mode == "Encrypt":
                st.code(aes_encrypt(text, key))
            else:
                st.code(aes_decrypt(text, key))
        except Exception as e:
            st.error(f"Error: {e}")

# -------------- DES Encryption -------------- #
elif method == "DES":
    st.subheader("DES Encryption")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
    text = st.text_area("Enter text")
    key = st.text_input("Enter key (up to 8 characters)")
    if st.button("Run DES"):
        try:
            if mode == "Encrypt":
                st.code(des_encrypt(text, key))
            else:
                st.code(des_decrypt(text, key))
        except Exception as e:
            st.error(f"Error: {e}")

# -------------- RSA Encryption -------------- #
elif method == "RSA":
    st.subheader("RSA Encryption")
    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)
    text = st.text_area("Enter text")
    if st.button("Run RSA"):
        try:
            if mode == "Encrypt":
                st.code(rsa_encrypt(text))
            else:
                st.code(rsa_decrypt(text))
        except Exception as e:
            st.error(f"Error: {e}")



# Footer
st.markdown("---")
st.caption("Use the sidebar to switch between encryption methods | Built using Streamlit | Part of my Cybersecurity Projects Portfolio")
