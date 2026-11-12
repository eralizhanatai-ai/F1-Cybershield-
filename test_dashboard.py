"""Тесты связи интерфейса с ядром. Запуск: python -m unittest -v"""
import json
import random
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock
from urllib.request import Request, urlopen

import dashboard
import main as core
from authentication import create_signature
from dashboard import ShieldSession
from simulator import generate_message

KEY = b"training-key"


def signed(message):
    return {"message": message, "signature": create_signature(message, KEY)}


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = ShieldSession(data_dir=self.tmp.name, write_files=False, rng=random.Random(7), run_thread=False)
        self.s.control("start")  # без фонового потока: пакеты отправляем вручную

    def tearDown(self):
        self.s.shutdown()
        self.tmp.cleanup()

    def next_message(self, car="car_01", source="car_sensor_01"):
        return generate_message(self.s._take_sequence(source), car, source)

    def test_normal_packet_is_allowed_and_updates_car(self):
        rec = self.s.handle_packet(signed(self.next_message()))
        self.assertEqual(rec["status"], "Allow")
        self.assertEqual(rec["hmac"], "passed")
        view = self.s.state_view("car_01")["car"]
        self.assertTrue(view["has_data"])
        self.assertEqual(view["last"]["speed"], rec["raw"]["message"]["speed"])

    def test_alert_is_accepted_with_warning(self):
        msg = self.next_message()
        msg["engine_temperature"] = 115.0
        rec = self.s.handle_packet(signed(msg))
        self.assertEqual(rec["status"], "Alert")
        self.assertIn("High engine temperature", rec["result"])
        self.assertEqual(self.s.state_view("car_01")["car"]["last"]["engine_temperature"], 115.0)

    def test_tampered_packet_blocked_and_does_not_update(self):
        self.s.handle_packet(signed(self.next_message()), received=100.0)
        before = self.s.state_view("car_01", now=100.5)["car"]
        packet = signed(self.next_message())
        packet["message"]["speed"] = 999
        rec = self.s.handle_packet(packet, received=100.5)
        self.assertEqual((rec["status"], rec["result"], rec["hmac"]), ("Blocked", "Authentication failed", "failed"))
        after = self.s.state_view("car_01", now=100.6)["car"]
        self.assertEqual(before["last"], after["last"])
        self.assertEqual(before["max_speed"], after["max_speed"])
        self.assertEqual(len(before["chart"]), len(after["chart"]))
        self.assertEqual(before["avg_speed"], after["avg_speed"])

    def test_replay_is_blocked(self):
        packet = signed(self.next_message())
        self.assertEqual(self.s.handle_packet(json.loads(json.dumps(packet)))["status"], "Allow")
        rec = self.s.handle_packet(packet)
        self.assertEqual((rec["status"], rec["result"]), ("Blocked", "Replay detected"))

    def test_replay_scenario_uses_core(self):
        self.s.send_scenario("normal", "car_01")
        rec = self.s.send_scenario("replay", "car_01")
        self.assertEqual(rec["result"], "Replay detected")

    def test_malformed_packets_have_undefined_source(self):
        for packet in ({"message": "hello"}, "hello", {"signature": "x"}):
            rec = self.s.handle_packet(packet)
            self.assertEqual(rec["status"], "Blocked")
            self.assertEqual(rec["hmac"], "not_checked")
            self.assertIsNone(rec["car_id"])
            self.assertIsNone(rec["source"])

    def test_two_cars_are_separate(self):
        self.s.handle_packet(signed(self.next_message("car_01", "car_sensor_01")))
        v2 = self.s.state_view("car_02")["car"]
        self.assertFalse(v2["has_data"])
        self.assertEqual(v2["chart"], [])
        self.s.handle_packet(signed(self.next_message("car_02", "car_sensor_02")))
        v1, v2 = self.s.state_view("car_01")["car"], self.s.state_view("car_02")["car"]
        self.assertEqual(len(v1["chart"]), 1)
        self.assertEqual(len(v2["chart"]), 1)
        self.assertNotEqual(v1["last"]["sequence"], None)

    def test_wrong_car_for_source_is_blocked(self):
        rec = self.s.handle_packet(signed(self.next_message("car_02", "car_sensor_01")))
        self.assertEqual(rec["result"], "Source does not match car")
        self.assertFalse(self.s.state_view("car_02")["car"]["has_data"])

    def test_time_weighted_average(self):
        car = dashboard.CarStats()
        def m(speed, seq):
            return {"speed": speed, "engine_temperature": 95, "sequence": seq,
                    "tyre_temperatures": dict.fromkeys(dashboard.WHEELS_RU, 90)}
        car.add(0.0, m(200, 1), [])
        car.add(1.0, m(300, 2), [])   # 1 с, средняя 250
        car.add(4.0, m(100, 3), [])   # разрыв 3 с: учитывается (не больше лимита)
        car.add(10.0, m(100, 4), [])  # разрыв 6 с: не учитывается
        self.assertAlmostEqual(car.average(), (250 * 1 + 200 * 3) / 4)

    def test_pause_keeps_sequence_and_replay_memory(self):
        self.s.send_scenario("normal", "car_01")
        seq_before = self.s.seq["car_sensor_01"]
        self.s.control("pause")
        self.assertEqual(self.s.state, "paused")
        self.s.control("resume")
        self.assertEqual(self.s.seq["car_sensor_01"], seq_before)
        rec = self.s.send_scenario("replay", "car_01")
        self.assertEqual(rec["result"], "Replay detected")

    def test_new_session_continues_numbering(self):
        rec = self.s.send_scenario("normal", "car_01")
        used = rec["sequence"]
        self.s.control("stop")
        self.s.control("start")
        self.assertGreater(self.s.seq["car_sensor_01"], used)
        self.assertEqual(self.s.counters, {"Allow": 0, "Alert": 0, "Blocked": 0})
        self.assertFalse(self.s.state_view("car_01")["car"]["has_data"])
        replay = signed(rec["raw"]["message"])
        self.assertEqual(self.s.handle_packet(replay)["result"], "Replay detected")

    def test_core_called_once_per_packet(self):
        with mock.patch.object(core, "process_packet", wraps=core.process_packet) as spy:
            rec = self.s.send_scenario("normal", "car_01")
            self.s.state_view("car_01")
            self.s.events_view("all")
            self.s.event_view(rec["id"])
            self.assertEqual(spy.call_count, 1)

    def test_files_written(self):
        s = ShieldSession(data_dir=self.tmp.name, write_files=True, run_thread=False)
        s.control("start")
        s.send_scenario("normal", "car_01")
        s.control("stop")
        data = json.loads((dashboard.Path(self.tmp.name) / "accepted_messages.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["status"], "Allow")


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.session = ShieldSession(data_dir=cls.tmp.name, write_files=False)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        cls.port = cls.server.server_address[1]
        cls.server.RequestHandlerClass = dashboard.make_handler(cls.session, cls.port)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.session.shutdown()
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, path, body=None, host=None):
        req = Request(f"http://127.0.0.1:{self.port}{path}",
                      data=None if body is None else json.dumps(body).encode(),
                      headers={"Content-Type": "application/json"} if body is not None else {})
        if host:
            req.add_header("Host", host)
        with urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def test_running_session_produces_events(self):
        self.assertTrue(self.call("/api/control", {"action": "start"})["ok"])
        time.sleep(1.3)
        self.call("/api/control", {"action": "pause"})
        state = self.call("/api/state?car=car_01")
        self.assertEqual(state["state"], "paused")
        self.assertGreater(state["counters"]["Allow"], 0)
        frozen = self.call("/api/events")["total"]
        time.sleep(0.8)
        self.assertEqual(self.call("/api/events")["total"], frozen)  # на паузе пакетов нет
        self.call("/api/control", {"action": "stop"})

    def test_foreign_host_rejected(self):
        with self.assertRaises(Exception):
            self.call("/api/state", host="evil.example")


if __name__ == "__main__":
    unittest.main()
