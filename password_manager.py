from cryptography.fernet import Fernet
import sqlite3

# Generate a key and instantiate a Fernet object
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# Create table
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (id INTEGER PRIMARY KEY, service TEXT, encrypted_password TEXT)''')


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()


def add_password(service, password):
    encrypted_password = encrypt_password(password)
    c.execute("INSERT INTO passwords (service, encrypted_password) VALUES (?, ?)", (service, encrypted_password))
    conn.commit()


def get_password(service):
    c.execute("SELECT encrypted_password FROM passwords WHERE service=?", (service,))
    result = c.fetchone()
    if result:
        return decrypt_password(result[0])
    return None


def delete_password(service):
    c.execute("DELETE FROM passwords WHERE service=?", (service,))
    conn.commit()


add_password('example.com', 'my_secure_password')
print(get_password('example.com'))
delete_password('example.com')

# It's important we don't hang the connection
conn.close()
