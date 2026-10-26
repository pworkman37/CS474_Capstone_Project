"""
SecureScan severity test: HIGH candidate
Demonstrates SQL injection through string concatenation.
"""
import sqlite3

def find_user(connection: sqlite3.Connection, username: str):
    # Unsafe: untrusted input is inserted directly into SQL.
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return connection.execute(query).fetchall()
