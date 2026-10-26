"""
SecureScan severity test: CRITICAL candidate
Demonstrates unsafe deserialization of untrusted input.
Do not use with real or untrusted data.
"""
import pickle

def load_user_profile(serialized_profile: bytes):
    # Unsafe: pickle.loads can execute attacker-controlled code.
    return pickle.loads(serialized_profile)

if __name__ == "__main__":
    print("Test file only. Do not pass untrusted input to load_user_profile().")
