# ==========================================
# create_db.py
# MySQL Database Setup for CRACKA NIDS
# ==========================================

import mysql.connector
from mysql.connector import Error


# ==========================================
# MySQL Configuration
# ==========================================

DB_CONFIG = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "mysql"          # Change this if your MySQL has a password
}

DATABASE = "nids_database"


# ==========================================
# Create Database
# ==========================================

def create_database():
    """Create the NIDS database if it does not exist."""

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DATABASE}` "
            "CHARACTER SET utf8mb4 "
            "COLLATE utf8mb4_unicode_ci"
        )

        cursor.close()
        conn.close()

        print(f"Database '{DATABASE}' is ready.")

    except Error as e:
        print("Error while creating database:", e)
        raise


# ==========================================
# Get Database Connection
# ==========================================

def get_connection():
    """Return a connection to the NIDS database."""

    try:
        connection_config = DB_CONFIG.copy()
        connection_config["database"] = DATABASE

        conn = mysql.connector.connect(**connection_config)

        return conn

    except Error as e:
        print("Error connecting to MySQL database:", e)
        raise


# ==========================================
# Create Tables
# ==========================================

def create_tables():
    """Create all required NIDS tables."""

    conn = None
    cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        # ------------------------------------------
        # Users Table
        # ------------------------------------------

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

        # ------------------------------------------
        # Packet Logs Table
        # ------------------------------------------

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
        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ==========================================
# Create Default Admin
# ==========================================

def create_default_admin():
    """Create default admin account if no users exist."""

    conn = None
    cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]

        if count == 0:

            cursor.execute("""
                INSERT INTO users
                (
                    fullname,
                    username,
                    email,
                    phone,
                    dob,
                    profession,
                    gender,
                    password
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                "System Administrator",
                "admin",
                "admin@crackanids.local",
                "0000000000",
                "2000-01-01",
                "IT Admin",
                "Other",
                "admin123"
            ))

            conn.commit()

            print("Default admin account created.")

        else:
            print("Users already exist. Default admin was not created.")

    except Error as e:
        print("Error while creating default admin:", e)
        raise

    finally:
        if cursor:
            cursor.close()

        if conn:
            conn.close()


# ==========================================
# Complete Database Initialization
# ==========================================

def initialize_database():
    """Create database, tables and default admin."""

    print("\n==========================================")
    print("   CRACKA NIDS - MySQL Database Setup")
    print("==========================================")

    create_database()
    create_tables()
    create_default_admin()

    print("==========================================")
    print("Database initialization completed.")
    print("==========================================\n")


# ==========================================
# Run Directly
# ==========================================

if __name__ == "__main__":
    initialize_database()