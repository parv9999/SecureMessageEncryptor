import streamlit as st
from encryption import generate_key, encrypt_message, decrypt_message
from qr_generator import generate_qr
from PIL import Image
import pyzxing  # Install pyzxing: pip install pyzxing
import os

st.title("🔒 Secure Message Encryptor")

menu = ["Home", "Generate Key", "Encrypt Message", "Decrypt Message", "Upload QR and Decrypt"]
choice = st.sidebar.selectbox("Menu", menu)

# Hardcoded password for decryption (you can change this)
DECRYPTION_PASSWORD = "1234"

def read_qr_from_image(uploaded_file):
    # Save uploaded file temporarily
    temp_file_path = "temp_uploaded_qr.png"
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    img = Image.open(temp_file_path)
    zx = pyzxing.BarCodeReader()
    result = zx.decode(temp_file_path)
    
    if result:
        return result[0]['parsed']  # Returns the decoded QR data
    else:
        return None

if choice == "Home":
    st.subheader("Welcome to Secure Message Encryptor!")
    st.write("Use the sidebar to navigate.")

elif choice == "Generate Key":
    st.subheader("Generate Encryption Key")
    if st.button("Generate Key"):
        generate_key()
        st.success("Secret Key generated and saved as 'secret.key'!")

elif choice == "Encrypt Message":
    st.subheader("Encrypt your Message")
    user_message = st.text_area("Enter your message here")

    if st.button("Encrypt"):
        if user_message:
            encrypted = encrypt_message(user_message)
            encrypted_clean = encrypted.decode()

            st.session_state['encrypted_clean'] = encrypted_clean

            st.success("Encrypted Message:")
            st.code(encrypted_clean)
        else:
            st.error("Please enter a message.")

    if 'encrypted_clean' in st.session_state:
        if st.button("Generate QR Code"):
            qr_filename = generate_qr(st.session_state['encrypted_clean'])
            st.image(qr_filename)

            with open(qr_filename, "rb") as file:
                st.download_button(
                    label="Download QR Code",
                    data=file,
                    file_name="encrypted_qr.png",
                    mime="image/png"
                )

elif choice == "Decrypt Message":
    st.subheader("Decrypt your Message")
    encrypted_message = st.text_area("Paste Encrypted Message Here")

    user_password = st.text_input("Enter Decryption Password", type="password")

    if st.button("Decrypt"):
        if encrypted_message:
            if user_password == DECRYPTION_PASSWORD:
                try:
                    encrypted_message = encrypted_message.encode()
                    decrypted = decrypt_message(encrypted_message)
                    st.success("Decrypted Message:")
                    st.code(decrypted)
                except Exception as e:
                    st.error(f"Decryption Failed! Error: {str(e)}. Make sure you have the correct key and encrypted text.")
            else:
                st.error("❌ Incorrect Password! Access Denied.")
        else:
            st.error("Please paste an encrypted message!")

elif choice == "Upload QR and Decrypt":
    st.subheader("Upload QR Image and Decrypt")

    uploaded_file = st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        qr_text = read_qr_from_image(uploaded_file)
        if qr_text:
            st.success("QR Code Scanned Successfully!")
            st.write("QR text: ", qr_text)  # Debug line
            st.code(qr_text)

            user_password = st.text_input("Enter Decryption Password", type="password")

            if st.button("Decrypt from QR"):
                if user_password == DECRYPTION_PASSWORD:
                    try:
                        decrypted = decrypt_message(qr_text.encode())
                        st.success("Decrypted Message:")
                        st.code(decrypted)
                    except Exception as e:
                        st.error(f"Decryption Failed! Error: {str(e)}. Make sure your key matches.")
                else:
                    st.error("❌ Incorrect Password! Access Denied.")
        else:
            st.error("Could not decode QR. Make sure the QR contains encrypted text.")
