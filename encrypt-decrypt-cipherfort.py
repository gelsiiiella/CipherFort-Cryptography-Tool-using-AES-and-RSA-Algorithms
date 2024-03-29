from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import streamlit as st 
import pyperclip

def aes_encrypt(plaintext, key):
    try:
        plaintext_bytes = plaintext.encode()
        key_bytes = key.encode()
        if len(key_bytes) != 16:  
            st.error("AES key must be 16 bytes (128 bits) long.")
            return
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return ciphertext.hex()
    except Exception as e:
        st.error(f"Error during AES encryption: {e}")

def aes_decrypt(ciphertext, key):
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
        key_bytes = key.encode()
        if len(key_bytes) != 16:  
            st.error("AES key must be 16 bytes (128 bits) long.")
            return

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()
    except Exception as e:
        st.error(f"Error during AES decryption: {e}")

def rsa_encrypt(plaintext, public_key):
    try:
        plaintext_bytes = plaintext.encode()
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(plaintext_bytes)

        return ciphertext.hex()
    except Exception as e:
        st.error(f"Error during RSA encryption: {e}")

def rsa_decrypt(ciphertext, private_key):
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(ciphertext_bytes)

        return plaintext.decode()
    except Exception as e:
        st.error(f"Error during RSA decryption: {e}")

def main_interface():
    st.title("CipherFort Encrypt and Decrypt")
    st.write("Encrypt and Decrypt your Text using this AES and RSA Tool")
    st.write("Select an encryption method:")
    method = st.radio("Method:", ("AES", "RSA"))
    if method == "AES":
        aes_interface()
    elif method == "RSA":
        rsa_interface()

def aes_interface():
    st.title('Advanced Encryption Standard (AES)')
    st.text('AES is a 128-bit symmetrical block cipher algorithm using substitution-permutation \nnetworks to generate ciphertext from plaintext with key lengths of 128, 192, \nor 256 bits.')
    plaintext = st.text_area("Enter Text to Encrypt/Decrypt: ")
    key = st.text_input("Enter AES Key: ")
    action = st.radio("Select Action:", ("Encrypt", "Decrypt"))

    if st.button("Submit"):
        if action == 'Encrypt':
            encrypted_text = aes_encrypt(plaintext, key)
            if encrypted_text:
                st.success("Encrypted Text:")
                st.text_area(label="", value=encrypted_text, height=100)
            copy_to_clipboard(encrypted_text)
        elif action == 'Decrypt':
            decrypted_text = aes_decrypt(plaintext, key)
            if decrypted_text:
                st.success("Decrypted Text:")
                st.text_area(label="", value=decrypted_text, height=100)
                st.info("Text copied to clipboard.")
            copy_to_clipboard(decrypted_text)


def rsa_interface():
    st.title('Rivest-Shamir-Adleman(RSA)')
    st.text('RSA is an asymmetric encryption algorithm that uses a key pair that is \nmathematically linked to encrypt and decrypt data. The public key is used for \nencryption while the private key is used for decryption.')
    plaintext = st.text_area("Enter Text to Encrypt/Decrypt: ")
    public_key = st.text_area("Enter Public Key: ")
    private_key = st.text_area("Enter Private Key: ")
    action = st.radio("Select Action:", ("Encrypt", "Decrypt"))

    if st.button("Submit"):
        if action == 'Encrypt':
            encrypted_text = rsa_encrypt(plaintext, public_key)
            if encrypted_text:
                st.success("Encrypted Text:")
                st.text_area(label="", value=encrypted_text, height=100)
            copy_to_clipboard(encrypted_text)
        elif action == 'Decrypt':
            decrypted_text = rsa_decrypt(plaintext, private_key)
            if decrypted_text:
                st.success("Decrypted Text:")
                st.text_area(label="", value=decrypted_text, height=100)
            copy_to_clipboard(decrypted_text)


def copy_to_clipboard(text):
        st.button("Copy to Clipboard")
        pyperclip.copy(text)

        


def main():
    main_interface()

if __name__ == "__main__":
    main()
