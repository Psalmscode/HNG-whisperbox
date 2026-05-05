import { useState, useEffect, useRef, useCallback } from "react";

const BASE = "https://whisperbox.koyeb.app";

/* ─── Encoding helpers ─────────────────────────────────────────────────── */
const b64enc = buf =>
  btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer)));
const b64dec = s => {
  const b = atob(s); const u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u.buffer;
};

/* ─── Crypto ────────────────────────────────────────────────────────────── */
const genRSAKeyPair = () =>
  crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
    true, ["encrypt", "decrypt"]
  );

const genSalt = () => crypto.getRandomValues(new Uint8Array(16));

const deriveWrapKey = async (password, salt) => {
  const km = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    km, { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]
  );
};

/* Export private key as PKCS8, then wrap with AES-KW — all in one step */
const wrapPrivKey = async (privateKey, wrappingKey) =>
  b64enc(await crypto.subtle.wrapKey("pkcs8", privateKey, wrappingKey, "AES-KW"));

const unwrapPrivKey = (wrappedB64, wrappingKey) =>
  crypto.subtle.unwrapKey(
    "pkcs8", b64dec(wrappedB64), wrappingKey,
    { name: "AES-KW" },
    { name: "RSA-OAEP", hash: "SHA-256" },
    true, ["decrypt"]
  );

const exportPubKey = async k => b64enc(await crypto.subtle.exportKey("spki", k));
const importPubKey = b =>
  crypto.subtle.importKey("spki", b64dec(b), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);

const encryptMsg = async (text, recipPubB64, selfPubB64) => {
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, new TextEncoder().encode(text));
  const rawAes = await crypto.subtle.exportKey("raw", aes);
  const [rk, sk] = await Promise.all([importPubKey(recipPubB64), importPubKey(selfPubB64)]);
  const [ek, eks] = await Promise.all([
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, rk, rawAes),
    crypto.subtle.encrypt({ name: "RSA-OAEP" }, sk, rawAes),
  ]);
  return { ciphertext: b64enc(ct), iv: b64enc(iv), encryptedKey: b64enc(ek), encryptedKeyForSelf: b64enc(eks) };
};

const decryptMsg = async (payload, privKey, isSender) => {
  const ekB64 = isSender ? payload.encryptedKeyForSelf : payload.encryptedKey;
  const rawAes = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, b64dec(ekB64));
  const aes = await crypto.subtle.importKey("raw", rawAes, { name: "AES-GCM" }, false, ["decrypt"]);
  return new TextDecoder().decode(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64dec(payload.iv) }, aes, b64dec(payload.ciphertext))
  );
};

/* ─── API ───────────────────────────────────────────────────────────────── */
const api = async (method, path, body, token) => {
  const h = { "Content-Type": "application/json" };
  if (token) h["Authorization"] = `Bearer ${token}`;
  const r = await fetch(`${BASE}${path}`, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || `Error ${r.status}`);
  return d;
};

/* ─── Helpers ───────────────────────────────────────────────────────────── */
const fmtTime = iso => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const fmtLabel = iso => {
  const d = new Date(iso), t = new Date();
  if (d.toDateString() === t.toDateString()) return fmtTime(iso);
  const y = new Date(t); y.setDate(t.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return "Yesterday";
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
};
const initials = name => name?.split(" ").slice(0, 2).map(w => w[0]).join("").toUpperCase() || "?";
const hue = str => [...(str || "")].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;

/* ─── CSS ───────────────────────────────────────────────────────────────── */
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Cinzel:wght@500;600&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #050a14;
  --sb:        #070d1c;
  --surface:   #0c1527;
  --surface2:  #101e35;
  --bord:      #162035;
  --bord2:     #1e2f4d;
  --accent:    #4b8bff;
  --accentd:   #2d6ce8;
  --glow:      rgba(75,139,255,.15);
  --sent-bg:   #0d2254;
  --sent-b:    #1a3a8f;
  --recv-bg:   #0c1527;
  --recv-b:    #162035;
  --txt:       #cdd9f5;
  --txt2:      #5a7099;
  --txt3:      #2d4060;
  --green:     #22c55e;
  --red:       #f87171;
  --mono:      'JetBrains Mono', monospace;
  --ui:        'DM Sans', sans-serif;
  --serif:     'Cinzel', serif;
}

body { background: var(--bg); color: var(--txt); font-family: var(--ui); }

/* ── Auth ── */
.auth-wrap {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: radial-gradient(ellipse 80% 60% at 50% 0%, rgba(75,139,255,.07) 0%, transparent 70%), var(--bg);
}
.auth-card {
  width: 420px; background: var(--sb); border: 1px solid var(--bord2);
  border-radius: 16px; padding: 40px; position: relative; overflow: hidden;
}
.auth-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
}
.auth-logo {
  font-family: var(--serif); font-size: 22px; color: var(--txt); letter-spacing: 3px;
  text-transform: uppercase; text-align: center; margin-bottom: 6px;
}
.auth-tagline {
  font-family: var(--mono); font-size: 10px; color: var(--txt2); text-align: center;
  letter-spacing: 2px; margin-bottom: 32px; text-transform: uppercase;
}
.auth-tabs { display: flex; gap: 0; margin-bottom: 28px; border: 1px solid var(--bord2); border-radius: 8px; overflow: hidden; }
.auth-tab {
  flex: 1; padding: 10px; background: none; border: none; color: var(--txt2);
  font-family: var(--ui); font-size: 13px; cursor: pointer; transition: all .2s; letter-spacing: .5px;
}
.auth-tab.active { background: var(--surface2); color: var(--txt); }
.auth-tab:hover:not(.active) { background: rgba(255,255,255,.03); }

.field { margin-bottom: 16px; }
.field label { display: block; font-size: 11px; color: var(--txt2); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; font-family: var(--mono); }
.field input {
  width: 100%; padding: 11px 14px; background: var(--surface); border: 1px solid var(--bord2);
  border-radius: 8px; color: var(--txt); font-family: var(--ui); font-size: 14px; outline: none;
  transition: border-color .2s, box-shadow .2s;
}
.field input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--glow); }
.field input::placeholder { color: var(--txt3); }

.btn-primary {
  width: 100%; padding: 12px; background: var(--accent); border: none; border-radius: 8px;
  color: #fff; font-family: var(--ui); font-size: 14px; font-weight: 500; cursor: pointer;
  transition: background .2s, transform .1s; letter-spacing: .3px; margin-top: 8px;
}
.btn-primary:hover { background: var(--accentd); }
.btn-primary:active { transform: scale(.99); }
.btn-primary:disabled { opacity: .5; cursor: not-allowed; }
.auth-err { color: var(--red); font-size: 12px; margin-top: 12px; text-align: center; font-family: var(--mono); }

.pwd-wrap { position: relative; }
.pwd-wrap input { padding-right: 42px; }
.pwd-toggle {
  position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
  background: none; border: none; cursor: pointer; color: var(--txt2); padding: 4px;
  display: flex; align-items: center; transition: color .2s;
}
.pwd-toggle:hover { color: var(--txt); }

/* ── App layout ── */
.app { display: flex; height: 100vh; overflow: hidden; }

/* ── Sidebar ── */
.sidebar {
  width: 300px; min-width: 300px; background: var(--sb); border-right: 1px solid var(--bord);
  display: flex; flex-direction: column; overflow: hidden;
}
.sb-header {
  padding: 20px 16px 14px; border-bottom: 1px solid var(--bord); flex-shrink: 0;
  display: flex; align-items: center; gap: 10px;
}
.sb-logo { font-family: var(--serif); font-size: 15px; letter-spacing: 2px; flex: 1; color: var(--txt); }
.ws-dot {
  width: 7px; height: 7px; border-radius: 50%; background: var(--green); flex-shrink: 0;
  transition: background .3s;
}
.ws-dot.off { background: var(--txt3); }
.btn-logout {
  background: none; border: 1px solid var(--bord2); border-radius: 6px; color: var(--txt2);
  font-size: 11px; font-family: var(--mono); padding: 5px 10px; cursor: pointer; transition: all .2s;
}
.btn-logout:hover { border-color: var(--red); color: var(--red); }

.search-box { padding: 12px 14px; border-bottom: 1px solid var(--bord); flex-shrink: 0; }
.search-input {
  width: 100%; padding: 8px 12px; background: var(--surface); border: 1px solid var(--bord2);
  border-radius: 8px; color: var(--txt); font-family: var(--ui); font-size: 13px; outline: none;
  transition: border-color .2s;
}
.search-input:focus { border-color: var(--accent); }
.search-input::placeholder { color: var(--txt3); }

.convo-list { flex: 1; overflow-y: auto; padding: 6px 0; }
.convo-list::-webkit-scrollbar { width: 3px; }
.convo-list::-webkit-scrollbar-track { background: transparent; }
.convo-list::-webkit-scrollbar-thumb { background: var(--bord2); border-radius: 2px; }

.convo-item {
  display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer;
  transition: background .15s; position: relative;
}
.convo-item:hover { background: rgba(255,255,255,.03); }
.convo-item.active { background: var(--surface); }
.convo-item.active::before {
  content: ''; position: absolute; left: 0; top: 8px; bottom: 8px;
  width: 2px; background: var(--accent); border-radius: 0 2px 2px 0;
}

.avatar {
  width: 38px; height: 38px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  font-size: 13px; font-weight: 500; font-family: var(--ui);
}
.convo-info { flex: 1; min-width: 0; }
.convo-name { font-size: 13px; font-weight: 500; color: var(--txt); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.convo-user { font-size: 11px; color: var(--txt2); font-family: var(--mono); margin-top: 1px; }
.convo-time { font-size: 10px; color: var(--txt3); font-family: var(--mono); flex-shrink: 0; }

.search-section { padding: 8px 14px 4px; }
.search-label { font-size: 10px; color: var(--txt3); font-family: var(--mono); letter-spacing: 1px; text-transform: uppercase; margin-bottom: 4px; }

.sb-me {
  padding: 12px 14px; border-top: 1px solid var(--bord); flex-shrink: 0;
  display: flex; align-items: center; gap: 9px;
}
.me-name { font-size: 12px; font-weight: 500; color: var(--txt); }
.me-user { font-size: 10px; color: var(--txt2); font-family: var(--mono); }
.enc-badge {
  font-size: 9px; font-family: var(--mono); color: var(--accent); letter-spacing: 1px;
  border: 1px solid rgba(75,139,255,.3); border-radius: 4px; padding: 2px 6px; flex-shrink: 0;
}

/* ── Chat ── */
.chat { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg); }

.chat-header {
  padding: 16px 24px; border-bottom: 1px solid var(--bord); display: flex;
  align-items: center; gap: 12px; flex-shrink: 0; background: var(--sb);
}
.chat-header-info { flex: 1; }
.chat-header-name { font-size: 14px; font-weight: 500; color: var(--txt); }
.chat-header-sub { font-size: 11px; color: var(--txt2); font-family: var(--mono); margin-top: 2px; }
.e2ee-pill {
  font-size: 9px; font-family: var(--mono); letter-spacing: 1px; text-transform: uppercase;
  padding: 4px 9px; border-radius: 20px; border: 1px solid rgba(75,139,255,.25);
  color: var(--accent); background: rgba(75,139,255,.07); flex-shrink: 0;
}

.msg-list {
  flex: 1; overflow-y: auto; padding: 24px 24px 8px; display: flex; flex-direction: column; gap: 4px;
}
.msg-list::-webkit-scrollbar { width: 3px; }
.msg-list::-webkit-scrollbar-thumb { background: var(--bord2); border-radius: 2px; }

.msg-date-sep {
  text-align: center; font-size: 10px; font-family: var(--mono); color: var(--txt3);
  letter-spacing: 1px; margin: 10px 0 6px; display: flex; align-items: center; gap: 10px;
}
.msg-date-sep::before, .msg-date-sep::after { content: ''; flex: 1; height: 1px; background: var(--bord); }

.msg-row { display: flex; margin-bottom: 2px; }
.msg-row.sent { justify-content: flex-end; }
.msg-row.recv { justify-content: flex-start; }
.msg-row.sent + .msg-row.sent { margin-top: -1px; }

.bubble {
  max-width: 68%; padding: 9px 14px; border-radius: 14px; position: relative;
  font-size: 14px; line-height: 1.55; word-break: break-word;
}
.bubble.sent {
  background: var(--sent-bg); border: 1px solid var(--sent-b);
  border-bottom-right-radius: 4px; color: #c8dcff;
}
.bubble.recv {
  background: var(--recv-bg); border: 1px solid var(--recv-b);
  border-bottom-left-radius: 4px; color: var(--txt);
}
.bubble.pending { opacity: .6; }
.bubble-meta {
  font-size: 10px; font-family: var(--mono); color: var(--txt3); margin-top: 4px;
  display: flex; align-items: center; gap: 5px;
}
.bubble.sent .bubble-meta { justify-content: flex-end; }
.lock-icon { color: rgba(75,139,255,.5); font-size: 9px; }

/* ── Empty state ── */
.chat-empty {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px;
}
.chat-empty-logo { font-family: var(--serif); font-size: 28px; letter-spacing: 4px; color: var(--txt3); }
.chat-empty-sub { font-size: 12px; font-family: var(--mono); color: var(--txt3); letter-spacing: 1px; }
.chat-empty-hint {
  font-size: 11px; color: var(--txt3); text-align: center; max-width: 260px;
  line-height: 1.7; margin-top: 4px;
}

.loading-msgs {
  flex: 1; display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-family: var(--mono); color: var(--txt3); letter-spacing: 1px;
}

/* ── Input bar ── */
.input-bar {
  padding: 14px 20px 18px; border-top: 1px solid var(--bord); background: var(--sb); flex-shrink: 0;
  display: flex; align-items: flex-end; gap: 10px;
}
.msg-input {
  flex: 1; background: var(--surface); border: 1px solid var(--bord2); border-radius: 12px;
  padding: 11px 16px; color: var(--txt); font-family: var(--ui); font-size: 14px;
  resize: none; outline: none; max-height: 120px; line-height: 1.5;
  transition: border-color .2s, box-shadow .2s;
}
.msg-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--glow); }
.msg-input::placeholder { color: var(--txt3); }

.btn-send {
  width: 42px; height: 42px; border-radius: 10px; background: var(--accent); border: none;
  cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  transition: background .2s, transform .1s; color: #fff;
}
.btn-send:hover { background: var(--accentd); }
.btn-send:active { transform: scale(.95); }
.btn-send:disabled { opacity: .4; cursor: not-allowed; }

/* ── Scrollbar (Firefox) ── */
.convo-list, .msg-list { scrollbar-width: thin; scrollbar-color: var(--bord2) transparent; }

/* ── Animations ── */
@keyframes fadeUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
.auth-card { animation: fadeUp .35s ease-out; }
.bubble { animation: fadeUp .15s ease-out; }
.convo-item { animation: fadeUp .2s ease-out; }
`;

/* ─── Avatar ────────────────────────────────────────────────────────────── */
const AVATAR_COLORS = [
  ["#0d2254","#4b8bff"], ["#1a2206","#7abd2e"], ["#220d1a","#e05f9a"],
  ["#0d1e22","#22c5be"], ["#1e1a0d","#d4a83a"], ["#1a0d22","#9b6bff"],
];
function Avatar({ name, size = 38 }) {
  const h = hue(name) % AVATAR_COLORS.length;
  const [bg, fg] = AVATAR_COLORS[Math.floor(h)];
  return (
    <div className="avatar" style={{ width: size, height: size, minWidth: size, background: bg, color: fg }}>
      {initials(name)}
    </div>
  );
}

/* ─── AuthView ──────────────────────────────────────────────────────────── */
const EyeIcon = ({ open }) => open ? (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
  </svg>
) : (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

function AuthView({ tab, setTab, fields, setFields, err, busy, onLogin, onRegister }) {
  const [showPwd, setShowPwd] = useState(false);
  const set = k => e => setFields(f => ({ ...f, [k]: e.target.value }));
  const onKey = fn => e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); fn(); } };
  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-logo">WhisperBox</div>
        <div className="auth-tagline">End-to-end encrypted · Zero server knowledge</div>

        <div className="auth-tabs">
          <button className={`auth-tab${tab === "login" ? " active" : ""}`} onClick={() => setTab("login")}>Sign in</button>
          <button className={`auth-tab${tab === "register" ? " active" : ""}`} onClick={() => setTab("register")}>Create account</button>
        </div>

        {tab === "register" && (
          <div className="field">
            <label>Display name</label>
            <input value={fields.display_name} onChange={set("display_name")} placeholder="Your name" autoFocus />
          </div>
        )}
        <div className="field">
          <label>Username</label>
          <input value={fields.username} onChange={set("username")} placeholder="alice_92" autoFocus={tab === "login"} />
        </div>
        <div className="field">
          <label>Password</label>
          <div className="pwd-wrap">
            <input
              type={showPwd ? "text" : "password"} value={fields.password} onChange={set("password")}
              placeholder={tab === "register" ? "8+ characters" : "Your password"}
              onKeyDown={onKey(tab === "login" ? onLogin : onRegister)}
            />
            <button className="pwd-toggle" type="button" onClick={() => setShowPwd(v => !v)} tabIndex={-1} aria-label={showPwd ? "Hide password" : "Show password"}>
              <EyeIcon open={showPwd} />
            </button>
          </div>
        </div>

        {tab === "register" && (
          <p style={{ fontSize: 11, color: "var(--txt3)", fontFamily: "var(--mono)", marginBottom: 10, lineHeight: 1.6 }}>
            Keys are generated in your browser. Your password wraps the private key via PBKDF2 → AES-KW (PKCS8). The server never sees plaintext.
          </p>
        )}

        <button className="btn-primary" disabled={busy} onClick={tab === "login" ? onLogin : onRegister}>
          {busy ? (tab === "login" ? "Deriving keys…" : "Generating keypair…") : (tab === "login" ? "Sign in" : "Create account")}
        </button>
        {err && <div className="auth-err">{err}</div>}
      </div>
    </div>
  );
}

/* ─── AppView ───────────────────────────────────────────────────────────── */
function AppView({ user, convos, active, msgs, loadingMsgs, draft, setDraft, sending,
  searchQ, setSearchQ, searchRes, wsOnline, onOpenConvo, onSend, onLogout, bottomRef, inputRef }) {

  const displayList = searchQ.trim() ? searchRes : convos;
  const showSearch = !!searchQ.trim();

  const onKey = e => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); onSend(); }
  };

  /* Group messages by date */
  const grouped = [];
  let lastDate = null;
  for (const m of msgs) {
    const d = new Date(m.created_at).toDateString();
    if (d !== lastDate) { grouped.push({ type: "sep", date: d, iso: m.created_at }); lastDate = d; }
    grouped.push({ type: "msg", ...m });
  }

  const toConvoUser = item => ({
    user_id: item.user_id || item.id,
    display_name: item.display_name,
    username: item.username,
    public_key: item.public_key,
  });

  return (
    <div className="app">
      {/* ── Sidebar ── */}
      <div className="sidebar">
        <div className="sb-header">
          <span className="sb-logo">WHISPERBOX</span>
          <div className={`ws-dot${wsOnline ? "" : " off"}`} title={wsOnline ? "Connected" : "Connecting…"} />
          <button className="btn-logout" onClick={onLogout}>logout</button>
        </div>

        <div className="search-box">
          <input
            className="search-input" placeholder="Search users…"
            value={searchQ} onChange={e => setSearchQ(e.target.value)}
          />
        </div>

        <div className="convo-list">
          {showSearch && <div className="search-section"><div className="search-label">Users</div></div>}
          {displayList.map(item => {
            const cu = toConvoUser(item);
            const isActive = active?.user_id === cu.user_id;
            return (
              <div key={cu.user_id} className={`convo-item${isActive ? " active" : ""}`} onClick={() => onOpenConvo(cu)}>
                <Avatar name={cu.display_name} />
                <div className="convo-info">
                  <div className="convo-name">{cu.display_name}</div>
                  <div className="convo-user">@{cu.username}</div>
                </div>
                {item.last_message_at && (
                  <div className="convo-time">{fmtLabel(item.last_message_at)}</div>
                )}
              </div>
            );
          })}
          {displayList.length === 0 && searchQ.trim() && (
            <div style={{ padding: "20px 14px", fontSize: 12, color: "var(--txt3)", fontFamily: "var(--mono)", textAlign: "center" }}>
              No users found
            </div>
          )}
          {!searchQ && convos.length === 0 && (
            <div style={{ padding: "24px 14px", fontSize: 11, color: "var(--txt3)", fontFamily: "var(--mono)", textAlign: "center", lineHeight: 1.8 }}>
              No conversations yet.<br />Search for a user to start.
            </div>
          )}
        </div>

        <div className="sb-me">
          <Avatar name={user?.display_name} size={32} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="me-name">{user?.display_name}</div>
            <div className="me-user">@{user?.username}</div>
          </div>
          <div className="enc-badge">E2EE</div>
        </div>
      </div>

      {/* ── Chat pane ── */}
      <div className="chat">
        {!active ? (
          <>
            <div className="chat-empty">
              <div className="chat-empty-logo">WHISPERBOX</div>
              <div className="chat-empty-sub">Zero-knowledge messaging</div>
              <div className="chat-empty-hint">
                Search for a user in the sidebar to begin an encrypted conversation.
                Your private key never leaves this device.
              </div>
            </div>
          </>
        ) : (
          <>
            {/* Header */}
            <div className="chat-header">
              <Avatar name={active.display_name} />
              <div className="chat-header-info">
                <div className="chat-header-name">{active.display_name}</div>
                <div className="chat-header-sub">@{active.username}</div>
              </div>
              <div className="e2ee-pill">🔒 end-to-end encrypted</div>
            </div>

            {/* Messages */}
            {loadingMsgs ? (
              <div className="loading-msgs">decrypting messages…</div>
            ) : (
              <div className="msg-list">
                {grouped.length === 0 && (
                  <div style={{ margin: "auto", fontSize: 12, color: "var(--txt3)", fontFamily: "var(--mono)", textAlign: "center", lineHeight: 1.8 }}>
                    No messages yet.<br />Start the conversation.
                  </div>
                )}
                {grouped.map((item, i) => {
                  if (item.type === "sep") {
                    return (
                      <div key={`sep-${i}`} className="msg-date-sep">
                        {new Date(item.iso).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" })}
                      </div>
                    );
                  }
                  const sent = item.isSender;
                  return (
                    <div key={item.id} className={`msg-row ${sent ? "sent" : "recv"}`}>
                      <div className={`bubble ${sent ? "sent" : "recv"}${item.pending ? " pending" : ""}`}>
                        {item.text}
                        <div className="bubble-meta">
                          <span className="lock-icon">🔒</span>
                          <span>{item.pending ? "sending…" : fmtTime(item.created_at)}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
                <div ref={bottomRef} />
              </div>
            )}

            {/* Input */}
            <div className="input-bar">
              <textarea
                ref={inputRef}
                className="msg-input"
                rows={1}
                placeholder={`Message ${active.display_name}…`}
                value={draft}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={onKey}
              />
              <button className="btn-send" onClick={onSend} disabled={sending || !draft.trim()}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="22" y1="2" x2="11" y2="13"/>
                  <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ─── Root ──────────────────────────────────────────────────────────────── */
export default function WhisperBox() {
  const [screen, setScreen] = useState("auth");
  const [authTab, setAuthTab] = useState("login");
  const [fields, setFields] = useState({ username: "", display_name: "", password: "" });
  const [authErr, setAuthErr] = useState("");
  const [authBusy, setAuthBusy] = useState(false);

  const [user, setUser] = useState(null);
  const tok = useRef({ access: null, refresh: null });
  const privKey = useRef(null);

  const [convos, setConvos] = useState([]);
  const [active, setActive] = useState(null);
  const activeRef = useRef(null);
  const [msgs, setMsgs] = useState([]);
  const [loadingMsgs, setLoadingMsgs] = useState(false);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);

  const [searchQ, setSearchQ] = useState("");
  const [searchRes, setSearchRes] = useState([]);

  const wsRef = useRef(null);
  const [wsOnline, setWsOnline] = useState(false);

  const bottomRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => { activeRef.current = active; }, [active]);

  /* ── refresh ── */
  const refreshAccess = useCallback(async () => {
    try {
      const d = await api("POST", "/auth/refresh", { refresh_token: tok.current.refresh });
      tok.current.access = d.access_token;
      return d.access_token;
    } catch { setScreen("auth"); return null; }
  }, []);

  /* ── conversations ── */
  const loadConvos = useCallback(async () => {
    if (!tok.current.access) return;
    try { setConvos(await api("GET", "/conversations", null, tok.current.access)); } catch {}
  }, []);

  useEffect(() => { if (screen === "app") loadConvos(); }, [screen, loadConvos]);

  /* ── websocket ── */
  const connectWs = useCallback(() => {
    if (!tok.current.access) return;
    const socket = new WebSocket(`${BASE.replace("https","wss")}/ws?token=${tok.current.access}`);
    wsRef.current = socket;
    socket.onopen = () => setWsOnline(true);
    socket.onclose = async e => {
      setWsOnline(false);
      if (e.code === 4001) {
        const nt = await refreshAccess();
        if (nt) setTimeout(connectWs, 500);
      } else if (e.code === 4003) {
        setScreen("auth");
      } else {
        setTimeout(connectWs, 3000);
      }
    };
    socket.onmessage = async e => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.event === "message.receive" && privKey.current) {
          const isSender = false; // receive events are always from others
          const otherId = msg.from_user_id;
          let text = "[encrypted]";
          try { text = await decryptMsg(msg.payload, privKey.current, isSender); } catch {}
          const newMsg = { id: msg.id, from_user_id: msg.from_user_id, to_user_id: msg.to_user_id, text, isSender, created_at: msg.created_at };
          if (activeRef.current?.user_id === otherId) {
            setMsgs(p => [...p, newMsg]);
          }
          loadConvos();
        }
      } catch {}
    };
  }, [refreshAccess, loadConvos]);

  useEffect(() => {
    if (screen === "app") {
      connectWs();
      const iv = setInterval(refreshAccess, 14 * 60 * 1000);
      return () => { clearInterval(iv); wsRef.current?.close(); };
    }
  }, [screen, connectWs, refreshAccess]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  /* ── search ── */
  useEffect(() => {
    if (!searchQ.trim()) { setSearchRes([]); return; }
    const t = setTimeout(async () => {
      try {
        const d = await api("GET", `/users/search?q=${encodeURIComponent(searchQ)}`, null, tok.current.access);
        setSearchRes(d);
      } catch {}
    }, 350);
    return () => clearTimeout(t);
  }, [searchQ]);

  /* ── open conversation ── */
  const openConvo = useCallback(async cu => {
    setActive(cu); setMsgs([]); setLoadingMsgs(true); setSearchQ(""); setSearchRes([]);
    try {
      let pk = cu.public_key;
      if (!pk) {
        const d = await api("GET", `/users/${cu.user_id}/public-key`, null, tok.current.access);
        pk = d.public_key;
        setActive(a => ({ ...a, public_key: pk }));
        cu = { ...cu, public_key: pk };
      }
      const history = await api("GET", `/conversations/${cu.user_id}/messages?limit=50`, null, tok.current.access);
      const userId = user?.id; // capture for closure
      const dec = await Promise.allSettled(
        history.map(async m => {
          const isSender = m.from_user_id === userId;
          let text = "[encrypted]";
          try { text = await decryptMsg(m.payload, privKey.current, isSender); } catch {}
          return { ...m, text, isSender };
        })
      );
      setMsgs(dec.map(r => r.value).filter(Boolean).reverse());
    } catch (err) { console.error(err); }
    setLoadingMsgs(false);
    setTimeout(() => inputRef.current?.focus(), 100);
  }, [user]);

  /* ── send ── */
  const sendMsg = async () => {
    if (!draft.trim() || !active || sending) return;
    const text = draft.trim(); setDraft(""); setSending(true);
    const tempId = `t${Date.now()}`;
    setMsgs(p => [...p, { id: tempId, text, isSender: true, created_at: new Date().toISOString(), pending: true }]);
    try {
      let pk = active.public_key;
      if (!pk) {
        const d = await api("GET", `/users/${active.user_id}/public-key`, null, tok.current.access);
        pk = d.public_key; setActive(a => ({ ...a, public_key: pk }));
      }
      const payload = await encryptMsg(text, pk, user.public_key);
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ event: "message.send", to: active.user_id, payload }));
        setMsgs(p => p.map(m => m.id === tempId ? { ...m, pending: false } : m));
      } else {
        const d = await api("POST", "/messages", { to: active.user_id, payload }, tok.current.access);
        setMsgs(p => p.map(m => m.id === tempId ? { ...d, text, isSender: true } : m));
      }
      loadConvos();
    } catch { setMsgs(p => p.filter(m => m.id !== tempId)); setDraft(text); }
    setSending(false);
  };

  /* ── register ── */
  const doRegister = async () => {
    setAuthBusy(true); setAuthErr("");
    try {
      const salt = genSalt();
      const kp = await genRSAKeyPair();
      const wk = await deriveWrapKey(fields.password, salt);
      const [pubB64, wrappedB64] = await Promise.all([exportPubKey(kp.publicKey), wrapPrivKey(kp.privateKey, wk)]);
      const data = await api("POST", "/auth/register", {
        username: fields.username.toLowerCase(),
        display_name: fields.display_name || fields.username,
        password: fields.password,
        public_key: pubB64,
        wrapped_private_key: wrappedB64,
        pbkdf2_salt: b64enc(salt),
      });
      tok.current = { access: data.access_token, refresh: data.refresh_token };
      privKey.current = kp.privateKey;
      setUser(data.user);
      setScreen("app");
    } catch (e) { setAuthErr(e.message); }
    setAuthBusy(false);
  };

  /* ── login ── */
  const doLogin = async () => {
    setAuthBusy(true); setAuthErr("");
    try {
      const data = await api("POST", "/auth/login", { username: fields.username.toLowerCase(), password: fields.password });
      tok.current = { access: data.access_token, refresh: data.refresh_token };
      const wk = await deriveWrapKey(fields.password, b64dec(data.user.pbkdf2_salt));
      privKey.current = await unwrapPrivKey(data.user.wrapped_private_key, wk);
      setUser(data.user);
      setScreen("app");
    } catch (e) { setAuthErr(e.message); }
    setAuthBusy(false);
  };

  /* ── logout ── */
  const doLogout = async () => {
    try { await api("POST", "/auth/logout", { refresh_token: tok.current.refresh }, tok.current.access); } catch {}
    wsRef.current?.close();
    tok.current = { access: null, refresh: null }; privKey.current = null;
    setUser(null); setConvos([]); setMsgs([]); setActive(null);
    setScreen("auth");
  };

  return (
    <>
      <style>{CSS}</style>
      {screen === "auth" ? (
        <AuthView
          tab={authTab} setTab={setAuthTab}
          fields={fields} setFields={setFields}
          err={authErr} busy={authBusy}
          onLogin={doLogin} onRegister={doRegister}
        />
      ) : (
        <AppView
          user={user} convos={convos} active={active}
          msgs={msgs} loadingMsgs={loadingMsgs}
          draft={draft} setDraft={setDraft} sending={sending}
          searchQ={searchQ} setSearchQ={setSearchQ} searchRes={searchRes}
          wsOnline={wsOnline}
          onOpenConvo={openConvo} onSend={sendMsg} onLogout={doLogout}
          bottomRef={bottomRef} inputRef={inputRef}
        />
      )}
    </>
  );
}
