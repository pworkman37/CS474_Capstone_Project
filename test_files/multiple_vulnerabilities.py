import sqlite3
import pickle


# 2. Code Injection (CWE-95)
def calculate(expression):
    return eval(expression)


# 3. Insecure Deserialization (CWE-502)
def load_data(user_data):
    return pickle.loads(user_data)
