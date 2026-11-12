"""F1 CyberShield: веб-интерфейс учебной симуляции телеметрии.

Запуск:  python dashboard.py      (на Windows: py dashboard.py)
Затем откройте в браузере:  http://127.0.0.1:8050

Цепочка для каждого пакета:
    генерация (simulator.generate_message) -> номер пакета -> HMAC
    (authentication.create_signature) -> main.process_packet -> сохранение
    результата -> отображение на странице.

process_packet вызывается ровно один раз на пакет. Страница только читает
сохранённые результаты, поэтому перерисовка, фильтры и просмотр деталей
не могут случайно сработать как "повтор пакета".

Это учебная симуляция, а не подключение к настоящему болиду.
"""

import copy
import json
import os
import random
import threading
import time
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import main as core
from authentication import create_signature
from simulator import generate_message

HERE = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8050

SECRET_KEY = b"training-key"  # учебный ключ, тот же, что в main.py и simulator.py
CARS = (("car_01", "car_sensor_01"), ("car_02", "car_sensor_02"))
TICK_SECONDS = 0.5      # как часто каждый болид присылает пакет
HISTORY_LIMIT = 1000    # сколько последних событий хранится для таблицы
CHART_WINDOW_S = 60     # окно графика скорости
STALE_AFTER_S = 3.0     # через сколько секунд без данных показания считаются устаревшими
GAP_LIMIT_S = 3.0       # интервал больше этого не участвует в средней скорости
INCIDENT_CHANCE = 0.06  # вероятность тестового инцидента на пакет, если включены

# Сценарии генератора. Они описывают, КАК пакет был создан для проверки щита.
# Решение о пакете всегда принимает только main.process_packet.
SCENARIOS = {
    "normal": "Обычный пакет",
    "alert": "Значение за учебным порогом (подписано честно)",
    "tamper": "Подмена: скорость изменена после подписи",
    "replay": "Повтор: отправлен уже принятый пакет",
    "malformed": "Неправильный формат пакета",
    "unknown_source": "Чужой датчик (подписан, но не зарегистрирован)",
}
INCIDENT_SCENARIOS = ("alert", "tamper", "replay", "malformed", "unknown_source")

# Результаты, при которых process_packet отклонил пакет ДО проверки HMAC.
HMAC_NOT_CHECKED = {
    "Invalid packet format",
    "Missing message",
    "Invalid message format",
    "Missing signature",
    "Invalid signature type",
}

REASONS_RU = {
    "Invalid packet format": "Неверный формат пакета",
    "Missing message": "В пакете нет сообщения",
    "Invalid message format": "Неверный формат сообщения",
    "Missing signature": "Нет подписи",
    "Invalid signature type": "Неверный тип подписи",
    "Authentication failed": "Подпись не совпадает (HMAC)",
    "Invalid sequence": "Неверный номер пакета",
    "Replay detected": "Повтор пакета",
    "Missing Speed": "Нет скорости",
    "Missing Source": "Нет источника",
    "Missing engine temperature": "Нет температуры двигателя",
    "Missing tyre temperatures": "Нет температур шин",
    "Invalid source type": "Неверный тип источника",
    "Unknown source": "Неизвестный источник",
    "Missing or invalid car_id": "Нет или неверный car_id",
    "Unknown car": "Неизвестный болид",
    "Source does not match car": "Источник не принадлежит болиду",
    "Invalid data type": "Неверный тип данных скорости",
    "Invalid temperature data type": "Неверный тип температуры двигателя",
    "Invalid speed": "Отрицательная скорость",
    "Invalid tyre data format": "Неверный формат температур шин",
    "Unusual speed": "Необычно высокая скорость",
    "High engine temperature": "Высокая температура двигателя",
    "Low engine temperature": "Низкая температура двигателя",
}
WHEELS_RU = {
    "front_left": "передняя левая",
    "front_right": "передняя правая",
    "rear_left": "задняя левая",
    "rear_right": "задняя правая",
}
WHEEL_PREFIXES_RU = (
    ("Missing tyre temperature:", "Нет температуры шины"),
    ("Invalid tyre temperature type:", "Неверный тип температуры шины"),
    ("Non-finite tyre temperature:", "Недопустимое значение температуры шины"),
    ("Low tyre temperature:", "Низкая температура шины"),
    ("High tyre temperature:", "Высокая температура шины"),
)


def reason_ru(code):
    """Переводит строку результата ядра на русский. Исходный код тоже сохраняется."""
    if code in REASONS_RU:
        return REASONS_RU[code]
    for prefix, text in WHEEL_PREFIXES_RU:
        if code.startswith(prefix):
            wheel = code[len(prefix):].strip()
            return f"{text}: {WHEELS_RU.get(wheel, wheel)}"
    return code


def hmac_state(result):
    """Что известно о проверке HMAC по результату process_packet.

    check_signed_message проверяет подпись первой, до номера, полей и повтора.
    Поэтому любой результат, кроме ранних ошибок формата и Authentication failed,
    означает, что подпись проверена и совпала.
    """
    if isinstance(result, list):
        return "passed"
    if result == "Authentication failed":
        return "failed"
    if result in HMAC_NOT_CHECKED:
        return "not_checked"
    return "passed"


def _claimed(message, key):
    """Значение из непроверенного пакета: только если это строка или целое число."""
    if not isinstance(message, dict):
        return None
    value = message.get(key)
    if isinstance(value, str) or (type(value) is int):
        return value
    return None


class CarStats:
    """Принятая телеметрия одного болида. Сюда попадают только Allow и Alert."""

    def __init__(self):
        self.samples = deque(maxlen=600)  # (время, скорость) для графика
        self.last = None                  # последнее принятое сообщение
        self.max_speed = None
        self.area = 0.0                   # интеграл скорости по времени
        self.time = 0.0                   # время, учтённое в средней
        self.prev = None                  # предыдущая точка для средней

    def add(self, received, message, warnings):
        speed = float(message["speed"])
        self.samples.append((received, speed))
        self.max_speed = speed if self.max_speed is None else max(self.max_speed, speed)
        if self.prev is not None:
            dt = received - self.prev[0]
            if 0 < dt <= GAP_LIMIT_S:
                self.area += (speed + self.prev[1]) / 2 * dt
                self.time += dt
        self.prev = (received, speed)
        self.last = {
            "received": received,
            "speed": speed,
            "engine_temperature": float(message["engine_temperature"]),
            "tyres": {w: float(message["tyre_temperatures"][w]) for w in WHEELS_RU},
            "warnings": list(warnings),
            "sequence": message["sequence"],
        }

    def break_interval(self):
        """Пауза или остановка: следующий интервал не склеивается с предыдущим."""
        self.prev = None

    def average(self):
        return self.area / self.time if self.time > 0 else None


class ShieldSession:
    """Сессия симуляции: генерирует пакеты, отдаёт их ядру и хранит результаты."""

    def __init__(self, key=SECRET_KEY, data_dir=HERE, write_files=True, rng=None, run_thread=True):
        self.key = key
        self.run_thread = run_thread  # False: пакеты отправляются только вручную (для тестов)
        self.data_dir = Path(data_dir)
        self.write_files = write_files
        self.rng = rng or random.Random()
        self.lock = threading.RLock()
        self.state = "idle"  # idle | running | paused | ended
        self.incidents = False
        self.version = 0
        self._thread = None
        self._stop = threading.Event()
        self._dirty = False
        self._last_save = 0.0
        self._reset()

    # ---------- сессия ----------
    def _reset(self):
        self.events = deque(maxlen=HISTORY_LIMIT)
        self.next_id = 1
        self.counters = {"Allow": 0, "Alert": 0, "Blocked": 0}
        self.cars = {car_id: CarStats() for car_id, _ in CARS}
        self.accepted_records = []
        self.replayable = {car_id: deque(maxlen=30) for car_id, _ in CARS}
        self.seq = {source: self._next_free_sequence(source) for _, source in CARS}
        self.run_time = 0.0
        self.run_since = None
        self.frozen_at = None
        self.started_at = None
        self.version += 1

    @staticmethod
    def _next_free_sequence(source):
        """Новая сессия продолжает нумерацию после самого большого принятого номера.

        Память о повторах (main.seen_packets) при этом не очищается, поэтому
        старые пакеты по-прежнему будут блокироваться как повтор.
        """
        used = [seq for (src, seq) in core.seen_packets if src == source]
        return max(used, default=0) + 1

    def control(self, action):
        with self.lock:
            now = time.time()
            if action == "start" and self.state in ("idle", "ended"):
                self._reset()
                self.state = "running"
                self.started_at = now
                self.run_since = now
                self._ensure_thread()
            elif action == "pause" and self.state == "running":
                self.state = "paused"
                self.run_time += now - self.run_since
                self.run_since = None
                self.frozen_at = now
                for car in self.cars.values():
                    car.break_interval()
                self._save(force=True)
            elif action == "resume" and self.state == "paused":
                self.state = "running"
                self.run_since = now
                self.frozen_at = None
            elif action == "stop" and self.state in ("running", "paused"):
                if self.run_since is not None:
                    self.run_time += now - self.run_since
                self.run_since = None
                self.state = "ended"
                self.frozen_at = now
                for car in self.cars.values():
                    car.break_interval()
                self._save(force=True)
            else:
                return False
            self.version += 1
            return True

    def set_incidents(self, enabled):
        with self.lock:
            self.incidents = bool(enabled)
            self.version += 1

    def _ensure_thread(self):
        if not self.run_thread:
            return
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="simulation", daemon=True)
            self._thread.start()

    def shutdown(self):
        self._stop.set()
        with self.lock:
            self._save(force=True)

    def _loop(self):
        """Рабочий поток: страница не ждёт генерацию, она только читает результаты."""
        while not self._stop.is_set():
            with self.lock:
                if self.state == "running":
                    for car_id, _ in CARS:
                        scenario = "normal"
                        if self.incidents and self.rng.random() < INCIDENT_CHANCE:
                            scenario = self.rng.choice(INCIDENT_SCENARIOS)
                        self.send_scenario(scenario, car_id)
                    self._save()
            self._stop.wait(TICK_SECONDS)

    # ---------- генерация пакетов ----------
    def _take_sequence(self, source):
        seq = self.seq[source]
        self.seq[source] += 1
        return seq

    def build_packet(self, scenario, car_id):
        """Создаёт пакет для сценария. Возвращает None, если сценарий сейчас невозможен."""
        source = dict(CARS)[car_id]
        if scenario == "replay":
            if not self.replayable[car_id]:
                return None
            return copy.deepcopy(self.rng.choice(list(self.replayable[car_id])))
        if scenario == "malformed":
            if self.rng.random() < 0.5:
                return {"message": "hello"}
            message = generate_message(self._take_sequence(source), car_id, source)
            return {"message": message}  # подписи нет
        if scenario == "unknown_source":
            message = generate_message(1, car_id, "car_sensor_09")
            return {"message": message, "signature": create_signature(message, self.key)}

        message = generate_message(self._take_sequence(source), car_id, source)
        if scenario == "alert":
            kind = self.rng.choice(("engine", "tyre", "speed"))
            if kind == "engine":
                message["engine_temperature"] = round(self.rng.uniform(111, 118), 1)
            elif kind == "tyre":
                wheel = self.rng.choice(tuple(WHEELS_RU))
                message["tyre_temperatures"][wheel] = round(self.rng.uniform(111, 119), 1)
            else:
                message["speed"] = round(self.rng.uniform(305, 335), 1)
        packet = {"message": message, "signature": create_signature(message, self.key)}
        if scenario == "tamper":
            packet["message"]["speed"] = round(packet["message"]["speed"] + 40, 1)
        return packet

    def send_scenario(self, scenario, car_id):
        with self.lock:
            if scenario not in SCENARIOS or car_id not in dict(CARS):
                return None
            packet = self.build_packet(scenario, car_id)
            if packet is None:
                return None
            return self.handle_packet(packet, scenario)

    # ---------- единственная точка вызова ядра ----------
    def handle_packet(self, packet, scenario=None, received=None):
        with self.lock:
            received = time.time() if received is None else received
            raw = copy.deepcopy(packet)
            try:
                response = core.process_packet(packet, self.key)
            except Exception as error:  # ядро не должно падать, но поток интерфейса важнее
                response = {"message": {}, "result": f"Core error: {type(error).__name__}", "status": "Blocked"}
            status, result, message = response["status"], response["result"], response["message"]
            if self.write_files:
                core.write_security_log(message, result, status)

            accepted = status in ("Allow", "Alert")
            reasons = result if isinstance(result, list) else [result]
            record = {
                "id": self.next_id,
                "received": received,
                "status": status,
                "result": result,
                "reasons": [{"code": r, "text": reason_ru(r)} for r in reasons],
                "hmac": hmac_state(result),
                "accepted": accepted,
                # Для принятых пакетов ядро проверило car_id, source и sequence.
                # Для заблокированных это лишь то, что написано в пакете.
                "car_id": _claimed(message, "car_id"),
                "source": _claimed(message, "source"),
                "sequence": _claimed(message, "sequence"),
                "scenario": scenario,
                "scenario_text": SCENARIOS.get(scenario),
                "raw": raw,
            }
            self.next_id += 1
            self.events.appendleft(record)
            self.counters[status] = self.counters.get(status, 0) + 1

            if accepted:
                car_id = message["car_id"]
                self.cars[car_id].add(received, message, result)
                self.accepted_records.append({"message": message, "status": status, "warnings": result})
                self.replayable[car_id].append(raw)
                self._dirty = True
            self.version += 1
            return record

    # ---------- сохранение ----------
    def _save(self, force=False):
        if not self.write_files or not self._dirty:
            return
        now = time.time()
        if not force and now - self._last_save < 2.0:
            return
        path = self.data_dir / "accepted_messages.json"
        tmp = path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as file:
            json.dump(self.accepted_records, file, ensure_ascii=False, indent=4)
        os.replace(tmp, path)
        self._dirty = False
        self._last_save = now

    # ---------- данные для страницы ----------
    def _elapsed(self, now):
        extra = now - self.run_since if self.run_since is not None else 0.0
        return self.run_time + extra

    def state_view(self, car_id, now=None):
        with self.lock:
            now = time.time() if now is None else now
            ref = now if self.state == "running" else (self.frozen_at or now)
            car = self.cars.get(car_id)
            car_view = None
            if car is not None:
                last = car.last
                chart = [[round(t * 1000), s] for t, s in car.samples if ref - CHART_WINDOW_S <= t <= ref]
                car_view = {
                    "car_id": car_id,
                    "source": dict(CARS)[car_id],
                    "has_data": last is not None,
                    "last": None if last is None else {**last, "received_ms": round(last["received"] * 1000)},
                    "max_speed": car.max_speed,
                    "avg_speed": car.average(),
                    "avg_seconds": round(car.time, 1),
                    "stale": last is not None and (self.state != "running" or now - last["received"] > STALE_AFTER_S),
                    "chart": chart,
                    "chart_ref_ms": round(ref * 1000),
                }
            return {
                "version": self.version,
                "state": self.state,
                "incidents": self.incidents,
                "elapsed": self._elapsed(now),
                "counters": dict(self.counters),
                "stored": len(self.events),
                "history_limit": HISTORY_LIMIT,
                "car": car_view,
                "cars": [c for c, _ in CARS],
                "scenarios": SCENARIOS,
            }

    FILTERS = {
        "all": lambda r: True,
        "accepted": lambda r: r["status"] == "Allow",
        "alert": lambda r: r["status"] == "Alert",
        "blocked": lambda r: r["status"] == "Blocked",
    }

    def events_view(self, filt="all", offset=0, limit=8):
        with self.lock:
            test = self.FILTERS.get(filt, self.FILTERS["all"])
            rows = [r for r in self.events if test(r)]
            page = rows[offset:offset + limit]
            return {
                "total": len(rows),
                "offset": offset,
                "rows": [self._row(r) for r in page],
            }

    @staticmethod
    def _row(r):
        return {
            "id": r["id"],
            "received_ms": round(r["received"] * 1000),
            "status": r["status"],
            "car_id": r["car_id"],
            "source": r["source"],
            "sequence": r["sequence"],
            "accepted": r["accepted"],
            "reason": None if r["status"] == "Allow" else r["reasons"][0]["text"],
            "more": 0 if r["status"] == "Allow" else len(r["reasons"]) - 1,
        }

    def event_view(self, event_id):
        with self.lock:
            for r in self.events:
                if r["id"] == event_id:
                    out = dict(r)
                    out["received_ms"] = round(r["received"] * 1000)
                    return out
            return None


# ---------- HTTP ----------
def make_handler(session, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    page_path = HERE / "dashboard.html"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # не засоряем консоль запросами страницы
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self):
            if self.headers.get("Host") not in allowed_hosts:
                self._send(403, {"error": "forbidden host"})
                return False
            return True

        def do_GET(self):
            if not self._host_ok():
                return
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path in ("/", "/index.html"):
                self._send(200, page_path.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self._send(200, session.state_view(q.get("car", ["car_01"])[0]))
            elif url.path == "/api/events":
                try:
                    offset = max(0, int(q.get("offset", ["0"])[0]))
                    limit = min(50, max(1, int(q.get("limit", ["8"])[0])))
                except ValueError:
                    self._send(400, {"error": "bad paging"})
                    return
                self._send(200, session.events_view(q.get("filter", ["all"])[0], offset, limit))
            elif url.path == "/api/event":
                try:
                    event = session.event_view(int(q.get("id", ["0"])[0]))
                except ValueError:
                    event = None
                self._send(200 if event else 404, event or {"error": "not found"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._host_ok():
                return
            # application/json заставляет браузер делать preflight для чужих сайтов,
            # а мы его не разрешаем: другие сайты не смогут нажимать кнопки за вас.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._send(415, {"error": "json only"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "bad json"})
                return
            path = urlparse(self.path).path
            if path == "/api/control":
                self._send(200, {"ok": session.control(body.get("action"))})
            elif path == "/api/incidents":
                session.set_incidents(body.get("enabled") is True)
                self._send(200, {"ok": True})
            elif path == "/api/send":
                with session.lock:
                    if session.state != "running":
                        self._send(409, {"error": "Тестовый пакет можно отправить только во время симуляции"})
                        return
                    record = session.send_scenario(body.get("scenario"), body.get("car"))
                if record is None:
                    self._send(409, {"error": "Для повтора нужен хотя бы один принятый пакет этого болида"})
                else:
                    self._send(200, {"ok": True, "id": record["id"]})
            else:
                self._send(404, {"error": "not found"})

    return Handler


def run(port=PORT):
    os.chdir(HERE)  # security_log.txt из main.py пишется в папку проекта
    session = ShieldSession()
    server = ThreadingHTTPServer((HOST, port), make_handler(session, port))
    print(f"F1 CyberShield: откройте http://{HOST}:{port}  (остановка: Ctrl+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен")
    finally:
        session.shutdown()
        server.server_close()


if __name__ == "__main__":
    run()
