import hmac
import hashlib
import json 

def create_signature(message, secret_key):
    return hmac.new(
    secret_key,
    json.dumps(message, sort_keys=True).encode("utf-8"),
    hashlib.sha256
).hexdigest()

def verify_signature(message, received_signature, secret_key):
    if not isinstance(received_signature, str):
        return False

    if len(received_signature) != 64:
        return False

    if any(char not in "0123456789abcdef" for char in received_signature):
        return False

    expected_signature = create_signature(message, secret_key)
    return hmac.compare_digest(received_signature, expected_signature)