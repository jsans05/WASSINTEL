# ---------- Imports ----------
import os, time, json, uuid, re
import requests
import bcrypt
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager
from datetime import datetime, timezone
from pillow_avif import AvifImagePlugin
import base64
from pathlib import Path

ASSETS = Path(__file__).parent

def _basic_auth_header(username: str, password: str) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}

def n8n_headers() -> dict:
    cfg = st.secrets["n8n"]
    return {
        "Content-Type": "application/json",
        **_basic_auth_header(cfg["username"], cfg["password"]),
    }

def now_iso():
    # RFC 3339 / ISO8601 with timezone, e.g. '2025-08-19T19:32:10.123456+00:00'
    return datetime.now(timezone.utc).isoformat()

def merge_memory_text(base: str, delta: str, mode: str = "append") -> str:
        delta = (delta or "").strip()
        if not delta:
            return base or ""
        if mode == "replace":
            return delta
        # default: append with a blank line separator
        if not base:
            return delta
        return base.rstrip() + "\n\n" + delta

# ---------- Page config ----------x
st.set_page_config(page_title="MysteryMachine", page_icon="❓")

# ---------- Cookies ----------
cookie_secret = st.secrets.get("COOKIE_PASSWORD")
if not cookie_secret:
    st.error("COOKIE_PASSWORD missing in .streamlit/secrets.toml")
    st.stop()

cookies = EncryptedCookieManager(prefix="mystery_", password=cookie_secret)
if not cookies.ready():
    st.stop()  # wait for component

REMEMBER_DAYS = 120

# ---------- Auth ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def ensure_auth():
    # Auto-login from cookie if valid
    if not st.session_state.get("authenticated"):
        raw = cookies.get("remember")
        if raw:
            try:
                data = json.loads(raw)
                email = data.get("email")
                exp   = int(data.get("exp", 0))
                now   = int(time.time())
                if email and now < exp:
                    # Optional allow-lists
                    allowed_domains = set(st.secrets.get("ALLOWED_EMAIL_DOMAINS", []))
                    if allowed_domains:
                        dom = email.split("@")[-1].lower()
                        if dom not in {d.lower() for d in allowed_domains}:
                            raise ValueError("domain blocked")
                    st.session_state.authenticated = True
                    st.session_state.user = {"email": email, "display": email, "username": email}
            except Exception:
                pass  # ignore bad cookie

    # If already authed (via cookie or prior login), show badge + logout
    if st.session_state.get("authenticated") and st.session_state.get("user"):
        with st.sidebar:
            me = st.session_state.user
            st.success(f"Signed in as: {me['email']}")
            if st.button("Log out"):
                for k in ("authenticated","user","session_id","messages","active_conv_id","memory"):
                    st.session_state.pop(k, None)
                if "remember" in cookies:
                    del cookies["remember"]
                cookies.save()

                st.rerun()
        return  # allow app to render

    # 2) Login screen (block until success)
    st.title("🔒 Mystery Machine Login")
    c1, c2 = st.columns(2)
    with c1: email = st.text_input("Email", placeholder="you@company.com")
    with c2: password = st.text_input("Password", type="password")
    remember = st.checkbox("Remember me", value=True)

    if st.button("Sign in", type="primary", use_container_width=True):
        # Email format
        if not EMAIL_RE.match(email or ""):
            st.error("Please enter a valid email address.")
            st.stop()

        # Allow-lists (tolerant to list or string)
        def _normalize_list(val):
            if not val: return set()
            if isinstance(val, list): items = val
            elif isinstance(val, str):
                s = val.strip().lstrip("@")
                if s.startswith("[") and s.endswith("]"):
                    try: items = json.loads(s)
                    except Exception: items = [s]
                else:
                    items = [p.strip().lstrip("@") for p in s.split(",")]
            else:
                items = list(val)
            return {x.strip().lower() for x in items if isinstance(x, str) and x.strip()}

        allowed_domains = _normalize_list(st.secrets.get("ALLOWED_EMAIL_DOMAINS", []))
        allowed_emails  = _normalize_list(st.secrets.get("ALLOWED_EMAILS", []))

        if allowed_domains:
            domain = email.split("@")[-1].lower()
            if domain not in allowed_domains:
                st.error("This email domain is not allowed.")
                st.stop()
        if allowed_emails:
            if email.lower() not in allowed_emails:
                st.error("This email is not allowed.")
                st.stop()

        # Password check (shared hash) — define ok HERE
        shared_hash = st.secrets.get("SHARED_PASSWORD_HASH", "")
        ok = False
        try:
            ok = bool(shared_hash) and bcrypt.checkpw((password or "").encode(), shared_hash.encode())
        except Exception:
            ok = False

        if ok:
            st.session_state.authenticated = True
            st.session_state.user = {"email": email, "display": email, "username": email}
            if remember:
                exp = int(time.time()) + REMEMBER_DAYS * 24 * 60 * 60
                cookies["remember"] = json.dumps({"email": email, "exp": exp})
                cookies.save()
            st.rerun()
        else:
            st.error("Invalid email or password.")

    st.stop()  # block rest of app until logged in

# ✅ CALL AUTH BEFORE ANYTHING USES st.session_state.user
ensure_auth()

# ---------- Convenience/current user ----------
USER = st.session_state.user["username"]   # email string


# ---------- Config ----------

N8N_URL     = st.secrets["n8n"]["webhook_url"]
N8N_STATUS  = st.secrets["n8n"]["status_url"]

USE_STATUS_WEBHOOK = False

# Supabase (REST)
SUPABASE_URL      = st.secrets.get("SUPABASE_URL", os.getenv("SUPABASE_URL", ""))
SUPABASE_ANON_KEY = st.secrets.get("SUPABASE_ANON_KEY", os.getenv("SUPABASE_ANON_KEY", ""))

SB_HEADERS = {
    "apikey": SUPABASE_ANON_KEY,
    "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Prefer": "return=representation",  # <- add this
    # Optional if your tables aren't in 'public':
    # "Accept-Profile": "public",
    # "Content-Profile": "public",
}


# ---------- SB helpers (define before memory/bootstrap uses them) ----------
def sb_select(table, params):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.get(url, headers=SB_HEADERS, params=params, timeout=(5,10))
    if not r.ok:
        st.error(f"SELECT {table} failed: {r.status_code} {r.text}")
        r.raise_for_status()
    return r.json()

def sb_insert(table, rows):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.post(url, headers=SB_HEADERS, data=json.dumps(rows), timeout=(5,10))
    if not r.ok:
        st.error(f"INSERT {table} failed: {r.status_code} {r.text}")
        r.raise_for_status()
    return r.json()

def sb_update(table, data, where):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.patch(url, headers=SB_HEADERS, params=where, data=json.dumps(data), timeout=(5,10))
    if not r.ok:
        st.error(f"UPDATE {table} failed: {r.status_code} {r.text}")
        r.raise_for_status()
    return r.json()

def sb_delete(table, where):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.delete(url, headers=SB_HEADERS, params=where, timeout=(5,10))
    if not r.ok:
        st.error(f"DELETE {table} failed: {r.status_code} {r.text}")
        r.raise_for_status()
    # PostgREST returns empty body for delete; nothing to return

# ---------- Conversation helpers ----------
def list_conversations(username: str):
    return sb_select("conversations", {
        "select": "id,title,created_at,updated_at",
        "username": f"eq.{username}",
        "order": "updated_at.desc",
    })

def create_conversation(username: str, title: str = "New chat"):
    row = sb_insert("conversations", [{
        "username": username,
        "title": title,
        # include timestamps only if your table doesn't have defaults
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }])[0]
    return row["id"], row["title"]

def load_messages(conv_id: str):
    return sb_select("messages", {
        "select": "role,content,created_at",
        "conversation_id": f"eq.{conv_id}",
        "order": "created_at.asc",
    })

def rename_conversation(conv_id: str, new_title: str):
    sb_update("conversations", {"title": new_title, "updated_at": now_iso()}, {"id": f"eq.{conv_id}"})

def append_message(conv_id: str, role: str, content: str):
    sb_insert("messages", [{"conversation_id": conv_id, "role": role, "content": content}])
    sb_update("conversations", {"updated_at": now_iso()}, {"id": f"eq.{conv_id}"})

def delete_conversation(conv_id: str):
    """
    Deletes a conversation (and, if your FK isn't ON DELETE CASCADE, its messages).
    """
    # If your messages table FK is NOT set to ON DELETE CASCADE, uncomment this:
    # sb_delete("messages", {"conversation_id": f"eq.{conv_id}"})
    sb_delete("conversations", {"id": f"eq.{conv_id}"})

# ---------- Memory helpers ----------
def get_user_memory(username: str) -> str:
    rows = sb_select("user_memory", {"select": "memory", "username": f"eq.{username}"})
    return rows[0]["memory"] if rows else ""

def set_user_memory(username: str, memory_text: str):
    # upsert-like behavior
    rows = sb_select("user_memory", {"select": "username", "username": f"eq.{username}"})
    payload = {"memory": memory_text, "updated_at": now_iso()}
    if rows:
        sb_update("user_memory", payload, {"username": f"eq.{username}"})
    else:
        sb_insert("user_memory", [{"username": username, **payload}])

def rename_conversation(conv_id, new_title):
    sb_update("conversations", {"title": new_title, "updated_at": now_iso()}, {"id": f"eq.{conv_id}"})

def append_message(conv_id, role, content):
    sb_insert("messages", [{"conversation_id": conv_id, "role": role, "content": content}])
    sb_update("conversations", {"updated_at": now_iso()}, {"id": f"eq.{conv_id}"})

@st.dialog("Delete chat?")
def confirm_delete_dialog():
    conv_id  = st.session_state.get("del_id")
    title    = st.session_state.get("del_title", "this chat")

    st.error("This action is permanent.")
    st.markdown(f"Are you sure you'd like to delete **{title}**?")

    c1, c2 = st.columns(2)
    if c1.button("Delete permanently", type="primary", use_container_width=True):
        try:
            delete_conversation(conv_id)
            # if the deleted chat was open, clear local state
            if st.session_state.active_conv_id == conv_id:
                st.session_state.active_conv_id = None
                st.session_state.messages = []
            st.session_state.show_del = False
            st.success("Chat deleted.")
            st.rerun()
        except Exception as e:
            st.error(f"Delete failed: {e}")

    if c2.button("Cancel", use_container_width=True):
        st.session_state.show_del = False
        st.rerun()


# ---------- Session defaults (after helpers) ----------
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "active_conv_id" not in st.session_state:
    st.session_state.active_conv_id = None
if "messages" not in st.session_state:
    st.session_state.messages = []
if "memory" not in st.session_state:
    # Load once per session
    try:
        st.session_state.memory = get_user_memory(USER)
    except Exception:
        st.session_state.memory = {}

# ----------------- App shell -----------------
ICON = ASSETS / "MysteryMachineIcon.png"
st.logo(str(ICON), size="large")
# (Optional) also set the page icon consistently:
st.set_page_config(page_title="Mystery Machine", page_icon=str(ICON), layout="wide")
st.title("Mystery Machine")
st.caption("Prospect sponsors, generate insights, and ask about the database.")

with st.sidebar:
    st.header("💬 Chats")

    # new chat button
    if st.button("➕ New chat", use_container_width=True):
        conv_id, title = create_conversation(USER, title="New chat")
        st.session_state.active_conv_id = conv_id
        st.session_state.messages = []
        st.rerun()

    # list existing chats
    # list existing chats
    convs = list_conversations(USER)
    for c in convs:
        is_active = (c["id"] == st.session_state.active_conv_id)
        cols = st.columns([0.7, 0.15, 0.15])  # title | rename | delete
        label = f"**{c['title']}**" if is_active else c["title"]

        if cols[0].button(label, key=f"open_{c['id']}", use_container_width=True):
            st.session_state.active_conv_id = c["id"]
            st.session_state.messages = load_messages(c["id"])
            st.rerun()

        with cols[1]:
            if st.button("✏️", key=f"rename_{c['id']}"):
                new = st.text_input("Rename chat", c["title"], key=f"rn_in_{c['id']}")
                if new and new != c["title"]:
                    rename_conversation(c["id"], new)
                    st.rerun()

        with cols[2]:
            if st.button("🗑️", key=f"delete_{c['id']}"):
                st.session_state.del_id = c["id"]
                st.session_state.del_title = c["title"]
                st.session_state.show_del = True
                st.rerun()


    # Memory controls (optional)
    st.divider()
    st.subheader("🧠 Memory")
    mem_text = st.text_area(
        "User memory (free text)",
        value=st.session_state.get("memory", ""),
        height=180,
        placeholder="e.g., default athlete is Hunter; avoid Yamaha; focus on US brands…"
    )
    if st.button("Save memory"):
        try:
            set_user_memory(USER, mem_text)
            st.session_state.memory = mem_text
            st.success("Memory saved.")
        except Exception as e:
            st.error(f"Save failed: {e}")

if st.session_state.get("show_del"):
    confirm_delete_dialog()

# Rainbow divider with CSS gradient
st.markdown(
    """
    <hr style="
        border: none;
        height: 2px;
        background: linear-gradient(to right, red, orange, yellow, green, blue, indigo, violet);
        border-radius: 2px;
        margin-top: 1em;
        margin-bottom: 1em;
    ">
    """,
    unsafe_allow_html=True
)

st.image(ASSETS / "MysteryMachine.png", caption="Gunner's Little Art Project", use_container_width=True)

# ----------------- Poll helpers -----------------
def poll_status_webhook(job_id: str, max_wait_s: int = 90000):
    start = time.time()
    delay = 1.0
    while time.time() - start < max_wait_s:
        r = requests.get(N8N_STATUS, params={"job_id": job_id}, headers=n8n_headers(), timeout=(5, 10))
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "done":
            return data.get("result")
        if data.get("status") == "error":
            raise RuntimeError(data.get("error", "Unknown error"))
        time.sleep(delay)
        delay = min(delay + 0.5, 3.0)
    raise TimeoutError("Propython3 -m venv .venvessing took too long.")

def poll_supabase(job_id: str, max_wait_s: int = 90000):
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise RuntimeError("Supabase config missing. Set SUPABASE_URL and SUPABASE_ANON_KEY.")
    start = time.time()
    delay = 1.0
    url = f"{SUPABASE_URL}/rest/v1/sponsor_jobs"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Accept": "application/json",
    }
    params = {
        "select": "job_id,status,finished_at,result,error",
        "job_id": f"eq.{job_id}",
    }
    while time.time() - start < max_wait_s:
        r = requests.get(url, headers=headers, params=params, timeout=(5, 10))
        r.raise_for_status()
        rows = r.json()
        row = rows[0] if rows else None
        if row and row.get("status") == "done":
            return row.get("result")
        if row and row.get("status") == "error":
            raise RuntimeError(row.get("error", "Unknown error"))
        time.sleep(delay)
        delay = min(delay + 0.5, 3.0)
    raise TimeoutError("Processing took too long.")

# When a conversation is selected, load messages if empty
if st.session_state.active_conv_id and not st.session_state.messages:
    st.session_state.messages = load_messages(st.session_state.active_conv_id)

# Render transcript (local cache)
for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

# Chat input
if user_input := st.chat_input("The Mystery Machine Awaits"):
    # Ensure a conversation exists
    if not st.session_state.active_conv_id:
        # Create first chat with a reasonable title from the first message
        title = (user_input.strip()[:40] + "…") if len(user_input.strip()) > 40 else user_input.strip() or "New chat"
        conv_id, _ = create_conversation(USER, title=title)
        st.session_state.active_conv_id = conv_id

    conv_id = st.session_state.active_conv_id

    # Echo + persist user msg
    st.chat_message("user", avatar=ASSETS / "wbi.png").markdown(user_input)
    st.session_state.messages.append({"role": "user", "content": user_input})
    append_message(conv_id, "user", user_input)

    # CALL YOUR BACKEND as you already do...
    payload = {
        "session_id": st.session_state.session_id,  # keep if your backend needs it
        "user_input": user_input,
        "memory_text": st.session_state.memory,          # send memory if useful to the agent
        "username": USER,
        "conversation_id": st.session_state.active_conv_id
    }

    try:
        ack = requests.post(N8N_URL, json=payload, headers=n8n_headers(), timeout=(5,20))
        ack.raise_for_status()
        ack_json = ack.json() if ack.headers.get("content-type","").startswith("application/json") else {}
        job_id = ack_json.get("job_id")

        with st.spinner("Drinking Red Bull..."):
            # your existing poll_* function
            if USE_STATUS_WEBHOOK and job_id:
                result = poll_status_webhook(job_id, max_wait_s=330)
            elif job_id:
                result = poll_supabase(job_id, max_wait_s=330)
            else:
                result = "Processing in the background."

            if isinstance(result, dict) and "memory_update" in result:
                base = st.session_state.get("memory", "")
                new_mem = merge_memory_text(base, result["memory_update_text"], mode="append")
                set_user_memory(USER, new_mem)
                st.session_state.memory = new_mem
            elif isinstance(result, dict) and isinstance(result.get("memory_update"), dict):
                base = st.session_state.get("memory", "")
                delta = json.dumps(result["memory_update"], indent=2)
                new_mem = merge_memory_text(base, delta, mode="append")
                set_user_memory(USER, new_mem)
                st.session_state.memory = new_mem
        rendered = json.dumps(result, indent=2) if isinstance(result, dict) else (result or "No result.")
        st.chat_message("assistant", avatar="MysteryMachineIcon.png").markdown(rendered)
        st.session_state.messages.append({"role": "assistant", "content": rendered})
        append_message(conv_id, "assistant", rendered)

        # Optional: auto‑rename conversation from first prompt
        if len(list_conversations(USER)) and st.session_state.messages and len(st.session_state.messages) == 2:
            title = (st.session_state.messages[0]["content"].strip()[:40] + "…")
            rename_conversation(conv_id, title)

    except Exception as e:
        st.chat_message("assistant").write(f"⚠️ Error: {e}")


    # ... inside your try: after 'result' is available but before 'rendered = ...'
    if isinstance(result, dict) and isinstance(result.get("memory_update_text"), str):
        base = st.session_state.get("memory", "")
        new_mem = merge_memory_text(base, result["memory_update_text"], mode="append")
        set_user_memory(USER, new_mem)         # persist to Supabase (text column)
        st.session_state.memory = new_mem      # update local cache

    # (Optional backwards‑compat if n8n still sends memory_update as JSON)
    
