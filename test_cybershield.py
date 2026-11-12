import unittest
from main import get_warnings
from authentication import create_signature, verify_signature

class TestWarnings(unittest.TestCase):
    def test_normal_values(self):
        result = get_warnings(250, 95)
        self.assertEqual(result, [])

    def test_two_warnings(self):
        result = get_warnings(315, 120)
        self.assertEqual(
            result,
            ["Unusual speed", "High engine temperature"]
        )

    def test_low_engine_temperature(self):
        result = get_warnings(250, -10)
        self.assertEqual(
            result,
            ["Low engine temperature"]
        )
class TestAuthentication(unittest.TestCase):
    def test_valid_signature(self):
        key = b"test-key"
        message = {
            "source": "car_sensor_01",
            "speed": 250, 
            "engine_temperature": 95
        }

        signature = create_signature(message, key)
        is_valid = verify_signature(message, signature, key)

        self.assertEqual(is_valid, True)

    def test_tampered_message(self):
        key = b"test-key"
        message = {
            "source": "car_sensor_01",
            "speed": 250,
            "engine_temperature":95 
        }
        signature = create_signature(message, key)
        message["speed"] = 100
        is_valid = verify_signature(message, signature, key)
        self.assertEqual(is_valid, False)