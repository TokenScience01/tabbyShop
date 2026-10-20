#!/usr/bin/env python3
"""Local web UI, shop API proxy, and persistent-in-process shop monitor."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import json
import math
import os
import sys
import threading
import time
from datetime import datetime, timezone

if getattr(sys, "frozen", False):
    RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    APP_DIR = Path(sys.executable).resolve().parent
else:
    RESOURCE_DIR = Path(__file__).resolve().parent
    APP_DIR = RESOURCE_DIR
TARGET = "https://game.tabby.meme/api/shop"
TOKEN_FILE = APP_DIR / "config.local.json"
MONITOR_FILE = APP_DIR / "monitor.local.json"
_WALLET_ADDRESS = None
_WALLET_CACHE_LOCK = threading.Lock()


def secure_keyring():
    import keyring
    backend = keyring.get_keyring()
    if backend.priority <= 0 or (sys.platform == "darwin" and not type(backend).__module__.startswith("keyring.backends.macOS")):
        raise RuntimeError("没有可用的安全系统钥匙串后端，未保存私钥")
    return keyring
DEFAULT_CONFIG = {
    "interval": 5,
    "concurrency": 3,
    "qualities": ["L3"],
    "minPrice": 0,
    "maxPrice": 200,
    "budget": 200,
    "maxCount": 1,
}


def read_token():
    try:
        value = json.loads(TOKEN_FILE.read_text()).get("token", "").strip()
        return value if value.lower().startswith("bearer ") else (f"Bearer {value}" if value else "")
    except (OSError, ValueError, AttributeError):
        return ""


def save_token(value):
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if not value:
        return
    TOKEN_FILE.write_text(json.dumps({"token": value}, indent=2) + "\n")
    try:
        TOKEN_FILE.chmod(0o600)
    except OSError:
        pass


def wallet_address():
    global _WALLET_ADDRESS
    with _WALLET_CACHE_LOCK:
        if _WALLET_ADDRESS is not None:
            return _WALLET_ADDRESS
        try:
            keyring = secure_keyring()
            stored = keyring.get_password("tabby-shop-bsc", "private-key")
            if not stored:
                _WALLET_ADDRESS = ""
            else:
                from eth_account import Account
                _WALLET_ADDRESS = Account.from_key(stored).address
        except Exception:
            _WALLET_ADDRESS = ""
        return _WALLET_ADDRESS


def import_wallet(private_key):
    global _WALLET_ADDRESS
    from eth_account import Account
    keyring = secure_keyring()
    key = private_key.strip()
    if key.startswith("0x"):
        key = key[2:]
    if len(key) != 64:
        raise ValueError("私钥格式无效")
    account = Account.from_key(key)
    keyring.set_password("tabby-shop-bsc", "private-key", key)
    with _WALLET_CACHE_LOCK:
        _WALLET_ADDRESS = account.address
    return account.address


def clear_wallet():
    global _WALLET_ADDRESS
    keyring = secure_keyring()
    try:
        keyring.delete_password("tabby-shop-bsc", "private-key")
    except keyring.errors.PasswordDeleteError:
        pass
    with _WALLET_CACHE_LOCK:
        _WALLET_ADDRESS = ""


def rpc(method, params):
    endpoint = os.environ.get("TABBY_BSC_RPC", "https://bsc-dataseed.binance.org/")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=25) as response:
        payload = json.loads(response.read())
    if payload.get("error"):
        raise RuntimeError(payload["error"].get("message", "BSC RPC 请求失败"))
    return payload.get("result")


def _is_address(value):
    return isinstance(value, str) and len(value) == 42 and value.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in value[2:])


def execute_purchase(product, config):
    keyring = secure_keyring()
    from eth_account import Account
    private_key = keyring.get_password("tabby-shop-bsc", "private-key")
    if not private_key:
        raise RuntimeError("系统钥匙串中没有已导入的私钥")
    account = Account.from_key(private_key)
    quote_request = Request(TARGET + "/order", data=json.dumps({"productId": int(product["id"])}).encode(),
        headers=ShopMonitor._headers(read_token()), method="POST")
    with urlopen(quote_request, timeout=25) as response:
        payload = json.loads(response.read())
    order = payload.get("order", payload)
    if order.get("status") != "QUOTED" or int(order.get("productId", -1)) != int(product["id"]):
        raise RuntimeError("订单报价状态或商品 ID 无效")
    if int(order.get("chainId", 0)) != 56 or str(order.get("address", "")).lower() != account.address.lower():
        raise RuntimeError("报价账户或网络与导入的钱包不一致")
    token_address, recipient = order.get("token"), order.get("recipient")
    if not _is_address(token_address) or not _is_address(recipient):
        raise RuntimeError("报价中的代币地址或收款地址无效")
    raw = str(order.get("amountRaw", ""))
    if not raw.isdigit() or int(raw) <= 0 or int(raw) >= 1 << 256:
        raise RuntimeError("报价转账数量无效")
    amount = float(order.get("amount", "nan"))
    if not math.isfinite(amount) or amount < config["minPrice"] or amount >= config["maxPrice"]:
        raise RuntimeError("订单报价不在设定价格范围内")
    if amount + MONITOR.buy_total > config["budget"]:
        raise RuntimeError("订单报价将超过本次总预算")
    expires = order.get("expiresAt")
    if not expires or datetime.fromisoformat(expires.replace("Z", "+00:00")) <= datetime.now(timezone.utc):
        raise RuntimeError("订单报价已过期")
    chain_id = int(rpc("eth_chainId", []), 16)
    if chain_id != 56:
        raise RuntimeError(f"BSC RPC 返回了错误网络：{chain_id}")
    code = rpc("eth_getCode", [token_address, "latest"])
    if not code or code == "0x":
        raise RuntimeError("报价代币地址没有合约代码")
    decimals_data = rpc("eth_call", [{"to": token_address, "data": "0x313ce567"}, "latest"])
    decimals = int(decimals_data, 16)
    if not 0 <= decimals <= 36:
        raise RuntimeError("报价代币精度无效")
    amount_text = str(order.get("amount", ""))
    whole, _, fraction = amount_text.partition(".")
    fraction = fraction.rstrip("0")
    if len(fraction) > decimals:
        raise RuntimeError("报价精度超过代币支持范围")
    if int(whole) * (10 ** decimals) + int((fraction + "0" * decimals)[:decimals] or "0") != int(raw):
        raise RuntimeError("报价显示金额与链上转账数量不一致")
    data = "0xa9059cbb" + recipient[2:].lower().rjust(64, "0") + hex(int(raw))[2:].rjust(64, "0")
    nonce = int(rpc("eth_getTransactionCount", [account.address, "pending"]), 16)
    gas_price = int(rpc("eth_gasPrice", []), 16)
    gas_estimate = int(rpc("eth_estimateGas", [{"from": account.address, "to": token_address, "value": "0x0", "data": data}]), 16)
    transaction = {"chainId": 56, "nonce": nonce, "gasPrice": gas_price, "gas": (gas_estimate * 120 + 99) // 100,
        "to": token_address, "value": 0, "data": data}
    signed = Account.sign_transaction(transaction, private_key)
    tx_hash = rpc("eth_sendRawTransaction", ["0x" + signed.raw_transaction.hex()])
    return {"amount": amount, "txHash": tx_hash}


def normalized_config(data):
    if not isinstance(data, dict):
        raise ValueError("配置必须是 JSON 对象")
    cfg = dict(DEFAULT_CONFIG)
    cfg.update({k: data[k] for k in DEFAULT_CONFIG if k in data})
    if "qualities" not in data and "quality" in data:  # Migrate settings saved by older UI versions.
        cfg["qualities"] = [data["quality"]]
    if not isinstance(cfg["qualities"], list):
        raise ValueError("品质必须是多选列表")
    cfg["qualities"] = list(dict.fromkeys(cfg["qualities"]))
    cfg["interval"] = int(cfg["interval"])
    cfg["concurrency"] = int(cfg["concurrency"])
    cfg["minPrice"] = float(cfg["minPrice"])
    cfg["maxPrice"] = float(cfg["maxPrice"])
    cfg["budget"] = float(cfg["budget"])
    cfg["maxCount"] = int(cfg["maxCount"])
    if not 5 <= cfg["interval"] <= 3600:
        raise ValueError("扫描间隔必须在 5–3600 秒之间")
    if not 1 <= cfg["concurrency"] <= 20:
        raise ValueError("并发扫描线程数必须在 1–20 之间")
    if not cfg["qualities"] or any(q not in {"L1", "L2", "L3", "L4", "*"} for q in cfg["qualities"]):
        raise ValueError("至少选择一个有效品质")
    if "*" in cfg["qualities"]:
        cfg["qualities"] = ["*"]
    if not math.isfinite(cfg["minPrice"]) or not math.isfinite(cfg["maxPrice"]):
        raise ValueError("价格范围无效")
    if cfg["minPrice"] < 0 or cfg["maxPrice"] <= cfg["minPrice"]:
        raise ValueError("最高价必须大于等于最低价")
    if not math.isfinite(cfg["budget"]) or cfg["budget"] <= 0:
        raise ValueError("总预算必须大于 0")
    if not 1 <= cfg["maxCount"] <= 10:
        raise ValueError("最多购买件数必须在 1–10 之间")
    return cfg


class ShopMonitor:
    def __init__(self):
        self.lock = threading.RLock()
        self.wake = threading.Event()
        persisted = self._load()
        if os.environ.get("TABBY_SAFE_START") == "1":
            persisted = dict(persisted, enabled=False, autoBuyEnabled=False)
        self.config = normalized_config(persisted.get("config", DEFAULT_CONFIG))
        self.enabled = bool(persisted.get("enabled", False))
        self.status = "starting" if self.enabled else "stopped"
        self.error = ""
        self.last_scan = None
        self.products = []
        self.candidate = None
        self.product_count = 0
        self.revision = 0
        self.scan_count = 0
        self.events = []
        self.auto_buy_enabled = bool(persisted.get("autoBuyEnabled", False))
        self.buy_count = int(persisted.get("buyCount", 0))
        self.buy_total = float(persisted.get("buyTotal", 0))
        self.attempted_products = set(persisted.get("attemptedProducts", []))
        self.buy_lock = threading.Lock()
        self.event_callback = None
        threading.Thread(target=self._run, name="shop-monitor", daemon=True).start()
        if self.enabled:
            self.wake.set()

    def _load(self):
        try:
            return json.loads(MONITOR_FILE.read_text())
        except (OSError, ValueError):
            return {}

    def _persist(self):
        payload = {"enabled": self.enabled, "autoBuyEnabled": self.auto_buy_enabled,
                   "buyCount": self.buy_count, "buyTotal": self.buy_total,
                   "attemptedProducts": sorted(self.attempted_products), "config": self.config}
        temp = MONITOR_FILE.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2) + "\n")
        temp.replace(MONITOR_FILE)

    def configure(self, data):
        cfg = normalized_config(data)
        with self.lock:
            self.config = cfg
            self._persist()
            if self.enabled:
                self.wake.set()
        return self.snapshot()

    def start(self, data):
        cfg = normalized_config(data)
        with self.lock:
            self.config = cfg
            self.enabled = True
            self.status = "running"
            self.error = ""
            self._persist()
            self.wake.set()
        return self.snapshot()

    def stop(self):
        with self.lock:
            self.enabled = False
            self.auto_buy_enabled = False
            self.status = "stopped"
            self._persist()
            self.wake.set()
        return self.snapshot()

    def snapshot(self, include_products=False):
        with self.lock:
            state = {
                "enabled": self.enabled,
                "autoBuyEnabled": self.auto_buy_enabled,
                "buyCount": self.buy_count,
                "buyTotal": self.buy_total,
                "walletAddress": wallet_address(),
                "status": self.status,
                "error": self.error,
                "config": dict(self.config),
                "lastScan": self.last_scan,
                "productCount": self.product_count,
                "candidate": self.candidate,
                "revision": self.revision,
                "scanCount": self.scan_count,
                "events": list(self.events[:12]),
            }
            if include_products:
                state["products"] = self.products
            return state

    @staticmethod
    def _headers(authorization):
        return {
            "sec-ch-ua-platform": '"macOS"',
            "Authorization": authorization,
            "Referer": "https://game.tabby.meme/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
            "Content-Type": "application/json",
        }

    @staticmethod
    def _find_matches(products, config):
        matches = []
        for product in products:
            try:
                price = float(product.get("price"))
                matches_quality = "*" in config["qualities"] or product.get("qualityCode") in config["qualities"]
                if (matches_quality and product.get("state") == "ACTIVE" and product.get("market") is not False
                        and not product.get("reserved") and config["minPrice"] <= price < config["maxPrice"]):
                    matches.append(product)
            except (TypeError, ValueError):
                continue
        return matches

    def _scan_once(self, config):
        auth = read_token()
        if not auth:
            raise RuntimeError("本地 config.local.json 中没有 Bearer Token")
        def fetch_shop(_):
            request = Request(TARGET, headers=self._headers(auth), method="GET")
            with urlopen(request, timeout=25) as response:
                payload = json.loads(response.read())
            result = payload.get("products", [])
            if not isinstance(result, list):
                raise RuntimeError("商城响应中没有商品列表")
            return result

        with ThreadPoolExecutor(max_workers=config["concurrency"]) as pool:
            responses = list(pool.map(fetch_shop, range(config["concurrency"])))
        # Concurrent responses overlap heavily; retain the newest instance of each product.
        products_by_id = {}
        for result in responses:
            for index, item in enumerate(result):
                key = str(item.get("id", f"response-item-{index}"))
                products_by_id[key] = item
        products = list(products_by_id.values())
        matches = self._find_matches(products, config)
        matches.sort(key=lambda item: (float(item.get("price", 0)), -int(item.get("id", 0))))
        timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        candidate = matches[0] if matches else None
        with self.lock:
            self.products = products
            self.product_count = len(products)
            self.candidate = candidate
            self.last_scan = timestamp
            self.revision += 1
            self.scan_count += 1
            self.error = ""
            self.status = "running" if self.enabled else "stopped"
            label = (f"命中 {len(matches)} 件；最低价 {candidate.get('price')}" if candidate else "扫描完成；无符合商品")
            self.events.insert(0, {"time": timestamp, "ok": True, "label": label, "matches": len(matches)})
            self.events = self.events[:30]
            auto_buy_enabled = self.auto_buy_enabled
        if auto_buy_enabled and candidate:
            self._process_candidate(candidate, config)

    def set_auto_buy(self, enabled):
        if enabled and not wallet_address():
            raise ValueError("请先导入 BSC 私钥")
        with self.lock:
            self.auto_buy_enabled = bool(enabled)
            if enabled:
                self.buy_count = 0
                self.buy_total = 0.0
                self.attempted_products.clear()
                self.enabled = True
                self.status = "running"
                self.wake.set()
            self._persist()
        return self.snapshot()

    def _process_candidate(self, product, config):
        product_id = int(product.get("id", 0))
        with self.buy_lock:
            if not product_id or product_id in self.attempted_products:
                return
            self.attempted_products.add(product_id)
            with self.lock:
                if not self.auto_buy_enabled or self.buy_count >= config["maxCount"] or self.buy_total >= config["budget"]:
                    self.auto_buy_enabled = False
                    self._persist()
                    return
                self._persist()
            try:
                result = execute_purchase(product, config)
                with self.lock:
                    self.buy_count += 1
                    self.buy_total += result["amount"]
                    self.events.insert(0, {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                        "ok": True, "label": f"购买已提交 {product.get('itemName')} · {result['amount']}", "matches": 1,
                        "txHash": result["txHash"]})
                    if self.buy_count >= config["maxCount"] or self.buy_total >= config["budget"]:
                        self.auto_buy_enabled = False
                    self._persist()
                    self.events = self.events[:30]
                self.emit_event(
                    "purchase", "秒购交易已提交",
                    f"商品：**{product.get('itemName') or product.get('itemCode') or product_id}**\n\n"
                    f"价格：{result['amount']}\n交易哈希：`{result['txHash']}`",
                )
            except Exception as exc:
                with self.lock:
                    self.auto_buy_enabled = False
                    self.error = str(exc)
                    self.status = "error"
                    self.events.insert(0, {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
                        "ok": False, "label": f"自动购买已暂停：{self.error}", "matches": 0})
                    self._persist()
                    self.events = self.events[:30]

    def emit_event(self, event_key, title, detail):
        """Forward shop events without letting UI notification errors affect trading."""
        callback = self.event_callback
        if callback is None:
            return
        try:
            callback(event_key, title, detail)
        except Exception:
            pass

    def _run(self):
        while True:
            self.wake.wait()
            self.wake.clear()
            with self.lock:
                enabled = self.enabled
                config = dict(self.config)
            if not enabled:
                continue
            try:
                self._scan_once(config)
            except (HTTPError, URLError, TimeoutError, ValueError, RuntimeError, OSError) as exc:
                timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                with self.lock:
                    self.error = str(exc)
                    self.status = "error"
                    self.last_scan = timestamp
                    self.events.insert(0, {"time": timestamp, "ok": False, "label": self.error, "matches": 0})
                    self.events = self.events[:30]
            with self.lock:
                delay = self.config["interval"]
                enabled = self.enabled
            if enabled:
                self.wake.wait(delay)


MONITOR = ShopMonitor()


class Handler(BaseHTTPRequestHandler):
    def _authorization(self):
        value = self.headers.get("Authorization", "")
        if value:
            return value if value.lower().startswith("bearer ") else f"Bearer {value}"
        return read_token()

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_upstream(self, request):
        try:
            with urlopen(request, timeout=25) as upstream:
                body = upstream.read()
                status = upstream.status
                content_type = upstream.headers.get("Content-Type", "application/json")
        except HTTPError as exc:
            body, status = exc.read(), exc.code
            content_type = exc.headers.get("Content-Type", "application/json")
        except (URLError, TimeoutError) as exc:
            self._send_json(502, {"error": str(exc)})
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 16_384:
            raise ValueError("请求内容大小无效")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise ValueError("请求必须是 JSON 对象")
        return payload

    def do_GET(self):
        if self.path == "/api/shop":
            request = Request(TARGET, headers=ShopMonitor._headers(self._authorization()), method="GET")
            self._send_upstream(request)
            return
        if self.path == "/api/monitor/state":
            self._send_json(200, MONITOR.snapshot())
            return
        if self.path == "/api/monitor/products":
            state = MONITOR.snapshot(include_products=True)
            self._send_json(200, {"products": state.pop("products"), "revision": state["revision"], "lastScan": state["lastScan"]})
            return
        if self.path == "/api/wallet/status":
            self._send_json(200, {"address": wallet_address(), "available": bool(wallet_address())})
            return

        relative = "index.html" if self.path == "/" else self.path.lstrip("/")
        path = (RESOURCE_DIR / relative).resolve()
        if RESOURCE_DIR not in path.parents or not path.is_file() or path.name == "monitor.local.json":
            self.send_error(404)
            return
        body = path.read_bytes()
        content_type = "application/json" if path.suffix == ".json" else "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        try:
            payload = self._read_json()
            if self.path == "/api/wallet/import":
                address = import_wallet(str(payload.get("privateKey", "")))
                self._send_json(200, {"address": address})
                return
            if self.path == "/api/wallet/clear":
                clear_wallet()
                MONITOR.set_auto_buy(False)
                self._send_json(200, {"ok": True})
                return
            if self.path == "/api/monitor/auto-buy":
                self._send_json(200, MONITOR.set_auto_buy(bool(payload.get("enabled"))))
                return
            if self.path == "/api/monitor/config":
                self._send_json(200, MONITOR.configure(payload))
                return
            if self.path == "/api/monitor/start":
                authorization = self._authorization()
                if not authorization:
                    raise ValueError("需要 Bearer Token")
                save_token(authorization)
                self._send_json(200, MONITOR.start(payload))
                return
            if self.path == "/api/monitor/stop":
                self._send_json(200, MONITOR.stop())
                return
            if self.path not in ("/api/shop/order", "/api/shop/cancel-quote"):
                self.send_error(404)
                return
            if self.path == "/api/shop/cancel-quote":
                order_id = payload.get("orderId")
                valid_numeric_id = (isinstance(order_id, int) and not isinstance(order_id, bool)
                                    and order_id > 0)
                valid_string_id = (isinstance(order_id, str) and bool(order_id.strip())
                                   and len(order_id) <= 200
                                   and not any(ord(char) < 32 for char in order_id))
                if not (valid_numeric_id or valid_string_id):
                    raise ValueError("orderId 必须是有效的数字或字符串编号")
                request = Request(
                    TARGET + "/cancel-quote",
                    data=json.dumps({"orderId": order_id}).encode(),
                    headers=ShopMonitor._headers(self._authorization()),
                    method="POST",
                )
                self._send_upstream(request)
                return
            product_id = payload.get("productId")
            if isinstance(product_id, bool) or not isinstance(product_id, int) or product_id <= 0:
                raise ValueError("productId 必须是正整数")
            request = Request(
                TARGET + "/order",
                data=json.dumps({"productId": product_id}).encode(),
                headers=ShopMonitor._headers(self._authorization()),
                method="POST",
            )
            self._send_upstream(request)
        except Exception as exc:
            self._send_json(400, {"error": str(exc)})

    def log_message(self, fmt, *args):
        # Do not log request headers; they contain the Bearer Token.
        print("%s - %s" % (self.address_string(), fmt % args))


if __name__ == "__main__":
    port = int(os.environ.get("TABBY_PORT", "8766"))
    url = f"http://127.0.0.1:{port}"
    print(f"Tabby Shop monitor: {url}")
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if os.environ.get("TABBY_NO_BROWSER") != "1":
        import webbrowser
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping Tabby Shop monitor...")
    finally:
        server.server_close()
