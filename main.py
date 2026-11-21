from authentication import create_signature, verify_signature
from datetime import datetime
import json 
import math
from simulator import generate_message
from http.server import BaseHTTPRequestHandler, HTTPServer
allowed_sources = {"car_sensor_01", "car_sensor_02", "car_sensor_03"}
allowed_car_sources = {
    "car_01": {"car_sensor_01"},
    "car_02": {"car_sensor_02"}
}
seen_packets = set()
def write_security_log(message, result, status):
    if status == "Allow":
        return

    source = message.get("source", "UNKNOWN")
    speed = message.get("speed", "UNKNOWN")
    timestamp = datetime.now().strftime("%H:%M")

    with open("security_log.txt", "a", encoding="utf-8") as file:
        file.write(f"{source}:{result}:{speed}:{timestamp}:{status}\n")
def check_message(message): 
    if "speed" not in message:
        return "Missing Speed"
    elif "source" not in message:
        return "Missing Source"
    elif "engine_temperature" not in message:
        return "Missing engine temperature"
    elif "tyre_temperatures" not in message:
        return "Missing tyre temperatures"
    elif not isinstance(message["source"], str):
        return "Invalid source type"
    elif message["source"] not in allowed_sources:
        return "Unknown source"
    car_id = message.get("car_id")

    if not isinstance(car_id, str):
        return "Missing or invalid car_id"

    if car_id not in allowed_car_sources:
        return "Unknown car"

    if message["source"] not in allowed_car_sources[car_id]:
        return "Source does not match car"
    speed = message["speed"]
    temperature_result = check_engine_temperature(message["engine_temperature"])

   
            

    if type(speed) not in (int, float):
        return "Invalid data type"
    if temperature_result == "Invalid data type":
        return "Invalid temperature data type"
    

    
    if speed < 0:
        return "Invalid speed"

    tyre_result = check_tyre_temperatures(message["tyre_temperatures"])

    if not isinstance(tyre_result, list):
        return tyre_result

    warnings = get_warnings(speed, message["engine_temperature"])
    warnings.extend(tyre_result)

    return warnings
def check_signed_message(message, signature, secret_key):
    if not isinstance(signature, str):
        return "Invalid signature type"

    if not verify_signature(message, signature, secret_key):
        return "Authentication failed"
    
    sequence = message.get("sequence")

    if type(sequence) is not int or sequence < 1:
        return "Invalid sequence"
    
    result = check_message(message)

    if not isinstance(result, list):
        return result 

    packet_id = (message["source"], sequence)

    if packet_id in seen_packets: 
        return "Replay detected"

    seen_packets.add(packet_id)
    return result 

def check_engine_temperature(temperature):
    if type(temperature) not in (int, float):
        return "Invalid data type"
    elif temperature < 0:
        return "Low engine temperature"
    elif temperature > 110:
        return "High engine temperature"
    else:
        return "Normal engine temperature"

def check_tyre_temperatures(tyre_temperatures):
    if not isinstance(tyre_temperatures, dict):
        return "Invalid tyre data format"
   
    required_wheels = (
        "front_left",
        "front_right",
        "rear_left",
        "rear_right"
    )
    warnings = []

    for wheel in required_wheels:
        if wheel not in tyre_temperatures:
            return f"Missing tyre temperature:{wheel}"

        temperature = tyre_temperatures[wheel]

        if type(temperature) not in (int, float):
            return f"Invalid tyre temperature type: {wheel}"

        if isinstance(temperature, float) and not math.isfinite(temperature):
                    return f"Non-finite tyre temperature: {wheel}"
        
        if temperature < 70:
                    warnings.append(f"Low tyre temperature: {wheel}")
        elif temperature > 110:
                    warnings.append(f"High tyre temperature: {wheel}")
        

    return warnings 

def get_warnings(speed, engine_temperature):
    warnings = []
    if speed > 300:
        warnings.append("Unusual speed")
    if engine_temperature > 110:
        warnings.append("High engine temperature")
    if engine_temperature < 0:
        warnings.append("Low engine temperature")
    
    return warnings

def get_status(result):
    if isinstance(result, list):
        if result: 
            return  "Alert"
        else: 
            return "Allow"
    
    return "Blocked" 

def process_packet(packet, secret_key):
    if not isinstance(packet, dict):
        return {
            "message": {},
            "result": "Invalid packet format",
            "status": "Blocked"
        }
    if "message" not in packet:
        return {
            "message": {}, 
            "result": "Missing message", 
            "status": "Blocked"
        }
    if not isinstance(packet["message"], dict):
     return {
           "message": {}, 
            "result": "Invalid message format",
            "status": "Blocked"
            }
    if "signature" not in packet:
        return {
            "message": packet["message"],
            "result": "Missing signature",
            "status": "Blocked"
        }
    message = packet["message"]
    signature = packet["signature"]

    result = check_signed_message(message, signature, secret_key)

    return {
        "message": message, 
        "result": result, 
        "status": get_status(result)
    }

def run_server():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/telemetry":
                self.send_error(404, "Unknown endpoint")
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return

            if not 1 <= length <= 65536:
                self.send_error(400, "Invalid request size")
                return

            try:
                raw_data = self.rfile.read(length)
                packet = json.loads(raw_data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                write_security_log({}, "Invalid JSON", "Blocked")
                self.send_error(400, "Invalid JSON")
                return

            response = process_packet(packet, b"training-key")

            write_security_log(
                response["message"],
                response["result"],
                response["status"]
            )

            print(response["status"], response["result"])

            body = json.dumps(response).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    with HTTPServer(("127.0.0.1", 8000), Handler) as server:
        print("CyberShield running: http://127.0.0.1:8000")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")

if __name__ == "__main__":
    car_01_message = generate_message(1, "car_01", "car_sensor_01")
    car_02_message = generate_message(1, "car_02", "car_sensor_02")

    print("Car 1:", car_01_message)
    print("Car 2:", car_02_message)
    
    assert get_warnings(250, 95) == []
    assert get_warnings(315, 120) == ["Unusual speed", "High engine temperature"]

    normal_tyres = {
        "front_left": 94,
        "front_right": 96,
        "rear_left": 98,
        "rear_right": 97
    }

    

    messages = [
        {"source": "car_sensor_01", "speed":"hello", "engine_temperature":100, "tyre_temperatures": normal_tyres.copy()
        }, 
        {"source":"car_sensor_02", "speed":315, "engine_temperature":95,"tyre_temperatures": normal_tyres.copy()
        }, 
        {"source": "car_sensor_03", "speed":280, "engine_temperature":110,"tyre_temperatures": normal_tyres.copy()},
        {"source": "car_sensor_04"}, 
        {"source": "car_sensor_05", "speed":-20,"tyre_temperatures": normal_tyres.copy()}, 
        { "speed":260}, 
        {"source": "fake_sensor", "speed":250, "engine_temperature":105,"tyre_temperatures": normal_tyres.copy()}, 
        {"source": "car_sensor_01", "speed":250, "engine_temperature":90,"tyre_temperatures": normal_tyres.copy()},
        {"source": "car_sensor_01","speed":250, "engine_temperature":95,"tyre_temperatures": normal_tyres.copy()},
        {"source": "car_sensor_02", "speed":270, "engine_temperature":120,"tyre_temperatures": normal_tyres.copy()},
        {"source": "car_sensor_02", "speed": "hello", "engine_temperature": 120,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_03", "speed": 250, "engine_temperature": 120,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_01", "speed": 315, "engine_temperature": "hello","tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_02", "speed": 315, "engine_temperature": "hello","tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_01", "speed":250, "engine_temperature":95,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_03", "speed":250, "engine_temperature":120,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_02", "speed":250, "engine_temperature":-10,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_03", "speed":315, "engine_temperature":"Hello","tyre_temperatures": normal_tyres.copy()},
    {"source":"car_sensor_01", "speed":250,"tyre_temperatures": normal_tyres.copy()},
    {"source": "car_sensor_01", "speed": 315, "engine_temperature": 120,"tyre_temperatures": normal_tyres.copy()},
    {"source": ["car_sensor_01"], "speed": 250, "engine_temperature": 95,"tyre_temperatures": normal_tyres.copy()},
    {
    "source": "car_sensor_01",
    "speed": 250,
    "engine_temperature": 95,
    "tyre_temperatures": {
        "front_left": 94,
        "front_right": 96,
        "rear_left": 98,
        "rear_right": 97
    }
},
    ]
    allowed_messages = []


    simulation_key = b"training-key"

    signed_packets = []

    for sequence, outgoing_message in enumerate(messages, start=1):
        message_to_sign = outgoing_message.copy()
        message_to_sign["sequence"] = sequence 

        packet = {
            "message": message_to_sign, 
            "signature": create_signature(message_to_sign, simulation_key)
        } 
        signed_packets.append(packet)


    #signed_packets[-1]["message"]["speed"] = 100
    signed_packets.append(signed_packets[2].copy())
    signed_packets.append({"message": "hello"})

    for packet in signed_packets:
        response = process_packet(packet, simulation_key)
        message = response["message"]
        result = response["result"]
        status = response["status"]
        speed = message.get("speed", "UNKNOWN")

        if status == "Allow" or status == "Alert":
            record = {
                "message": message,
                "status": status,
                "warnings": result
            }
            allowed_messages.append(record)

        source = message.get("source", "UNKNOWN")
        timestamp = datetime.now().strftime("%H:%M")
        print(source, result, speed, timestamp, status)
        write_security_log(message, result, status)
        
    print("Allowed messages:", allowed_messages)

    with open("accepted_messages.json", "w", encoding="utf-8") as file:
        json.dump(allowed_messages, file, indent=4)

    test_key = b"training-key"

    test_message = {
        "source": "car_sensor_01", 
        "speed": 250, 
        "engine_temperature": 95
    }

    test_signature = create_signature(test_message, test_key)

    test_result = check_signed_message(test_message, test_signature, test_key)

    test_status = get_status(test_result)
    print("HMAC test:", test_result, test_status)
    write_security_log(test_message, test_result, test_status)