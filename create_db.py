# ==========================================
# create_db.py - MySQL setup for CRACKA NIDS
# Database and tables initialize karne ke liye helper script.
# Credentials can be set with environment variables: NIDS_DB_HOST, NIDS_DB_USER, NIDS_DB_PASSWORD
# ==========================================
import os
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash

# Default DB login details. Inko environment variable se override kiya jaa sakta hai.
DB_CONFIG = {
    "host": os.environ.get("NIDS_DB_HOST", "127.0.0.1"),
    "user": os.environ.get("NIDS_DB_USER", "root"),
    "password": os.environ.get("NIDS_DB_PASSWORD", "mysql"),
}
DATABASE = "nids_database"

# Base database scheme create karta hai if ye exist nahi karta
def create_database():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.close()
        conn.close()
        print(f"Database '{DATABASE}' is ready.")
    except Error as e:
        print("Error while creating database:", e)
        raise

# Active connection lene ke liye wrapper function jise baaki app files use karti hain
def get_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG, database=DATABASE)
    except Error as e:
        print("Error connecting to MySQL database:", e)
        raise

# User registration details aur live packet logging store karne ke liye do tables create karta hai
def create_tables():
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Table for storing user account info with hashed passwords
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(100),
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100),
                phone VARCHAR(20),
                dob VARCHAR(20),
                profession VARCHAR(100),
                gender VARCHAR(20),
                password VARCHAR(255) NOT NULL
            )
        """)
        
        # Table for storing saved live-sniffing packet histories with proper indexing
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50),
                session_id INT,
                packet_id INT,
                ip_address VARCHAR(100),
                protocol VARCHAR(30),
                prediction VARCHAR(50),
                confidence VARCHAR(30),
                date VARCHAR(30),
                time VARCHAR(30),
                INDEX idx_packet_username (username),
                INDEX idx_packet_session (username, session_id)
            )
        """)
        conn.commit()
        print("Tables created successfully.")
    except Error as e:
        print("Error while creating tables:", e)
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Pehli baar setup run hone par database me default "admin" account seed karta hai
def create_default_admin():
    """Create the default admin only when the users table is empty."""
    conn = cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            # Secure password format generate karke insert karta hai
            cursor.execute("""
                INSERT INTO users (fullname, username, email, phone, dob, profession, gender, password)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, ("System Administrator", "admin", "admin@crackanids.local", "0000000000",
                  "2000-01-01", "IT Admin", "Other", generate_password_hash("admin123")))
            conn.commit()
            print("Default admin created (username: admin / password: admin123) - change this password!")
        else:
            print("Users already exist. Default admin was not created.")
    except Error as e:
        print("Error while creating default admin:", e)
        raise
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# Main orchestration function, called jab app pehli baar boot hota hai
def initialize_database():
    print("\n==========================================")
    print("   CRACKA NIDS - MySQL Database Setup")
    print("==========================================")
    create_database()
    create_tables()
    create_default_admin()
    print("Database initialization completed.\n")

if __name__ == "__main__":
    initialize_database()