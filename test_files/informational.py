"""
SecureScan severity test: INFORMATIONAL candidate
Contains a security-related configuration choice that may merit review,
but is not necessarily a vulnerability by itself.
"""

def build_security_headers():
    # Informational example: header policy should be reviewed in context.
    # This function returns a minimal set and intentionally omits CSP.
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
