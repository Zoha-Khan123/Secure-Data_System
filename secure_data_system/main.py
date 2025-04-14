import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'logged_in' not in st.session_state: 
    st.session_state.logged_in = False

if "user_credentials" not in st.session_state:
    st.session_state.user_credentials = {}

if 'page' not in st.session_state:
    st.session_state.page = 'login'

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0


# Hashing function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Encryption
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decryption Function
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Login Function
def login():
    st.title("Login")
    with st.form("login"):
        login_user_name = st.text_input("Enter Username").strip()
        login_user_password = st.text_input("Enter Password", type="password").strip()
        hashed_password = hash_password(login_user_password)
        submitted = st.form_submit_button("Login")

        if submitted:
            if login_user_name and login_user_password:
                if login_user_name in st.session_state.user_credentials:
                    if st.session_state.user_credentials[login_user_name]["user_password"] == hashed_password:
                        st.session_state.logged_in = True
                        st.session_state.page = 'dashboard'
                        st.session_state.current_user = login_user_name
                        st.rerun()
                    else:
                        st.error("Incorrect password!")
                else:
                    st.error("This user does not exist!")
            else:
                st.error("All fields are required!")

    if st.button("Go to Sign Up"):
        st.session_state.page = 'signup'
        st.rerun()

# Sign Up Function
def sign_up():
    st.title("Sign Up")
    with st.form("signup"):
        user_name = st.text_input("Enter Username").strip()
        user_password = st.text_input("Enter Password", type="password").strip()
        hashed_password = hash_password(user_password)
        user_confirm_password = st.text_input("Enter Confirm Password", type="password").strip()
        submitted = st.form_submit_button("Sign Up")

        if submitted:
            if user_name in st.session_state.user_credentials:
                st.warning("This username already exists!")
            else:
                if user_name and user_password and user_confirm_password:
                    if user_password == user_confirm_password:
                        st.session_state.user_credentials[user_name] = {
                            "user_password": hashed_password
                        }
                        st.success("Sign Up Successful! Please log in.")
                        st.session_state.page = 'login'
                        st.rerun()
                    else:
                        st.error("Passwords do not match!")
                else:
                    st.error("All fields are required!")

    if st.button("Back to Login"):
        st.session_state.page = 'login'
        st.rerun()


# Insert Data Function
def insert_data():
    with st.form("insert_data"):
        user_id = st.session_state.current_user
        text = st.text_input("Enter text")
        passkey = st.text_input("Enter passkey", type="password")
        submitted = st.form_submit_button("Insert Data")

        if submitted:
            if text and passkey:
                hashed_passkey = hash_password(passkey)
                encrypted_text = encrypt_data(text)

                # Ensure user_id has a list to store multiple entries
                if user_id not in st.session_state.stored_data:
                    st.session_state.stored_data[user_id] = []

                # Append the new entry to the user's data list
                st.session_state.stored_data[user_id].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                })
                st.success("Data stored successfully!")
            else:
                st.error("All fields are required!")

# Retrieve Data Function
def retrieved_data():
    with st.form("retrieved_data"):
        user_id = st.session_state.current_user
        ret_passkey = st.text_input("Enter passkey", type="password").strip()
        submitted = st.form_submit_button("Retrieve Data")

        if submitted:
            if ret_passkey:
                hashed_passkey = hash_password(ret_passkey)
                if user_id in st.session_state.stored_data:
                    # Check if any entry matches the passkey
                    for entry in st.session_state.stored_data[user_id]:
                        if entry["passkey"] == hashed_passkey:
                           # Decrypt the encrypted text before displaying
                            decrypted_text = decrypt_data(entry["encrypted_text"])
                            st.write(decrypted_text)
                            st.success("Data retrieved successfully!")
                            st.session_state.failed_attempts = 0  # Reset failed attempts
                            return
                    # Increment failed attempts and show remaining attempts
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    st.error(f"Incorrect passkey! Attempts remaining: {remaining_attempts}")
                else:
                    st.error("No data found for this user!")
            else:
                st.error("Passkey is required!")

            # Check if failed attempts exceed 3
            if st.session_state.failed_attempts >= 3:
                st.error("Too many failed attempts! Redirecting to login page...")
                st.session_state.page = 'login'
                st.session_state.failed_attempts = 0  # Reset failed attempts
                st.rerun()

# Logout Function
def logout():
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.page = 'login'
        st.success("Logged out successfully!")
        st.rerun()


# Dashboard Function
def show_dashboard():
    st.title("Dashboard")
    st.write(f"Welcome, {st.session_state.current_user}!")
    insert_data()
    retrieved_data()
    logout()


# Routing Logic
if st.session_state.page == 'signup':
    sign_up()
elif st.session_state.page == 'login':
    login()
elif st.session_state.page == 'dashboard' and st.session_state.logged_in:
    show_dashboard()