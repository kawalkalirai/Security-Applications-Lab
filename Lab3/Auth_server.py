import socket
import threading
import hashlib
import pyotp


HOST = '0.0.0.0'
PORT = 5555 # The port I will use

# Database to store user data
USER_DB = {}

def hash_password(plaintext_password):

    hasher = hashlib.sha256()
    hasher.update(plaintext_password.encode('utf-8'))
    # Returns the hash
    return hasher.hexdigest()

def create_test_user(username, plain_password):

    # Generates the Base32 Secret
    secret_key = pyotp.random_base32()

    # Hashes the password
    hashed_pw = hash_password(plain_password)

    # Stores the passwords in the database and associates secrets with user accounts
    USER_DB[username] = {
        'password_hash': hashed_pw,
        'otp_secret': secret_key
    }

    print(f"--- USER CREATED: {username} ---")
    print(f"Secret Key: {secret_key}")
    print("(Enter this key into Google Authenticator manually)")
    print("--------------------------------")

def verify_login(username, password_input, otp_input):

    # Compare usernames
    if username not in USER_DB:
        return False, "User not found"

    stored_data = USER_DB[username]

    # Comparing the hash with the one stored (incorrect password)
    input_hash = hash_password(password_input)
    if input_hash != stored_data['password_hash']:
        return False, "Incorrect Password"

    # Compares secrets
    totp = pyotp.TOTP(stored_data['otp_secret'])

    # Gives users extra time to put in code
    if totp.verify(otp_input, valid_window=1):
        return True, "Login Successful!"
    else:
        return False, "Invalid or Expired OTP"

def handle_client_connection(client_socket, address):
    print(f"[NEW CONNECTION] {address} connected.")

    try:
        # Receives data from client
        data = client_socket.recv(1024).decode()

        # Split the string into 3 parts
        try:
            user, pwd, otp = data.split(',')
        except ValueError:
            client_socket.send("Error: Wrong data format".encode())
            return

        success, message = verify_login(user, pwd, otp)

        # Sends results back to client
        client_socket.send(message.encode())

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

def start_server():
    # Standard socket setup from previous labs
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    # Prompt user name and password
    create_test_user("kawal", "test123")

    print(f"[LISTENING] Server running on {HOST}:{PORT}")

    while True:
        # Accepts new connections
        client_sock, addr = server.accept()
        thread = threading.Thread(target=handle_client_connection, args=(client_sock, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
