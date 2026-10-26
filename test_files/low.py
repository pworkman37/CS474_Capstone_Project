"""
SecureScan severity test: LOW candidate
Demonstrates overly broad exception handling that can hide failures.
"""
def read_setting(settings: dict, key: str):
    try:
        return settings[key]
    except Exception:
        # Weak practice: catches unrelated errors and silently hides them.
        return None
