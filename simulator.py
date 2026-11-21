import random 

def generate_message(sequence, car_id, source):
    return {
        "car_id": car_id,
        "source": source,
        "sequence":sequence,
        "speed": round(random.uniform(200, 300), 1),
        "engine_temperature": round(random.uniform(90, 105), 1),
        "tyre_temperatures": {
            "front_left": round(random.uniform(85, 105), 1),
            "front_right": round(random.uniform(85, 105), 1),
            "rear_left": round(random.uniform(85, 105), 1),
            "rear_right": round(random.uniform(85, 105), 1)
        }
    }
if __name__ == "__main__":
    import json
    import time
    from pathlib import Path

    from authentication import create_signature
    from urllib.request import Request, urlopen

    simulation_key = b"training-key"
    accepted_messages = []

    cars = (
        ("car_01", "car_sensor_01"),
        ("car_02", "car_sensor_02")
    )

    for sequence in range(1, 11):
        for car_id, source in cars:
            message = generate_message(sequence, car_id, source)

            packet = {
                "message": message,
                "signature": create_signature(message, simulation_key)
            }

            request = Request(
                "http://127.0.0.1:8000/telemetry",
                data=json.dumps(packet).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urlopen(request, timeout=5) as http_response:
                response = json.loads(
                    http_response.read().decode("utf-8")
                )
            status = response["status"]

            print(
                car_id,
                "№", sequence,
                "speed:", message["speed"],
                "engine:", message["engine_temperature"],
                status,
                response["result"]
            )

            

            if status in ("Allow", "Alert"):
                accepted_messages.append({
                    "message": message,
                    "status": status,
                    "warnings": response["result"]
                })

        if sequence < 10:
            time.sleep(1)

    output_path = Path(__file__).with_name("accepted_messages.json")

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(accepted_messages, file, indent=4)

    print("Simulation ended. Accepted:", len(accepted_messages))