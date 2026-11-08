// NOF Monitoring Log - Netlify Function (API).
// LOGINS use no database: accounts are listed in the USERS environment variable (hashed passwords),
// and a signed cookie keeps people logged in. ENTRIES are saved in Netlify Blobs.
// Environment variables needed: SESSION_SECRET and USERS (see README).
import { getStore } from "@netlify/blobs";
import { pbkdf2Sync, randomUUID, timingSafeEqual, createHmac } from "node:crypto";

const store = getStore({ name: "nof", consistency: "strong" });
const SESSION_MS = 12 * 3600e3;
const send = (code, obj, extra) => new Response(JSON.stringify(obj), { status: code, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...(extra || {}) } });
const err = (c, m) => send(c, { error: m });
const str = (v, n) => String(v == null ? "" : v).slice(0, n);
const clean = d => ({ date: str(d.date, 10), nof: str(d.nof, 4), series: str(d.series, 2), type: ["issue", "obs", "clear"].includes(d.type) ? d.type : "issue", issue: str(d.issue, 2000), action: str(d.action, 2000), status: ["Outstanding", "Resolved", ""].includes(d.status) ? d.status : "" });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const pbk = (pw, saltHex) => pbkdf2Sync(String(pw), Buffer.from(saltHex, "hex"), 100000, 32, "sha256").toString("hex");
// USERS = "username:role:salt:hash,username:role:salt:hash"  (made with make-user.html)
const getUsers = () => (process.env.USERS || "").split(/[,;\n]+/).map(s => s.trim()).filter(Boolean).map(l => {
  const [u, role, salt, hash] = l.split(":");
  return { username: (u || "").toLowerCase(), role: role === "admin" ? "admin" : "officer", salt, hash };
}).filter(u => u.username && /^[0-9a-f]+$/i.test(u.salt || "") && /^[0-9a-f]{64}$/i.test(u.hash || ""));
const pub = u => ({ id: u.username, username: u.username, role: u.role, mustChange: false });
const secret = () => { const s = process.env.SESSION_SECRET || ""; if (s.length < 16) throw new Error("SESSION_SECRET not set"); return s; };
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString("base64url"); return b + "." + createHmac("sha256", secret()).update(b).digest("base64url"); };
const verify = t => {
  if (!t) return null; const [b, s] = t.split("."); if (!s) return null;
  if (!safeEq(s, createHmac("sha256", secret()).update(b).digest("base64url"))) return null;
  try { const p = JSON.parse(Buffer.from(b, "base64url").toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
};
const cookieOf = (req, n) => { for (const c of (req.headers.get("cookie") || "").split(";")) { const [k, ...v] = c.trim().split("="); if (k === n) return v.join("="); } return ""; };
// the cookie remembers the first 12 characters of the password hash, so changing a password (or removing a user) in USERS logs that person out
const sessionCookie = u => "sid=" + sign({ u: u.username, h: u.hash.slice(0, 12), exp: Date.now() + SESSION_MS }) + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + SESSION_MS / 1000;

// read-modify-write with optimistic locking, so two people saving at once never overwrite each other
async function mutate(key, fn, dflt) {
  for (let i = 0; i < 8; i++) {
    const cur = await store.getWithMetadata(key, { type: "text" });
    const val = cur ? JSON.parse(cur.data) : JSON.parse(JSON.stringify(dflt));
    const out = fn(val);
    if (out === false) return false;
    const r = await store.set(key, JSON.stringify(val), cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true });
    if (!r || r.modified !== false) return out === undefined ? true : out;
  }
  throw new Error("Busy, please retry");
}
const getJSON = async (key, dflt) => { const t = await store.get(key, { type: "text" }); return t ? JSON.parse(t) : dflt; };
const readBody = async req => { try { return await req.json(); } catch { return {}; } };
const MONTH = /^\d{4}-\d{2}$/;

export default async (req) => {
  const url = new URL(req.url), p = url.pathname.replace(/\/+$/, ""), m = req.method;
  try {
    if (m !== "GET" && !(req.headers.get("content-type") || "").startsWith("application/json")) return err(415, "JSON required");
    secret();
    if (p === "/api/login" && m === "POST") {
      const d = await readBody(req), un = str(d.username, 40).toLowerCase();
      const u = getUsers().find(x => x.username === un);
      const ok = u ? safeEq(pbk(d.password, u.salt), u.hash) : (pbk(d.password, "00"), false);
      if (!ok) { await sleep(700); return err(401, "Wrong username or password"); }
      return send(200, pub(u), { "Set-Cookie": sessionCookie(u) });
    }
    if (p === "/api/logout" && m === "POST") return send(200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
    if (!p.startsWith("/api/")) return err(404, "Not found");

    const tok = verify(cookieOf(req, "sid"));
    const me = tok && getUsers().find(x => x.username === tok.u && x.hash.slice(0, 12) === tok.h);
    if (!me) return err(401, "Please log in");

    if (p === "/api/me" && m === "GET") return send(200, pub(me));
    if (p === "/api/logs" && m === "GET") {
      const ms = str(url.searchParams.get("months"), 100).split(",").filter(x => MONTH.test(x)).slice(0, 4);
      const parts = await Promise.all(ms.map(x => getJSON("logs/" + x, [])));
      return send(200, parts.flat());
    }
    if (p === "/api/logs" && m === "POST") {
      const e = clean(await readBody(req));
      if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date) || !e.nof) return err(400, "Date and NOF are required");
      const month = e.date.slice(0, 7);
      const entry = { ...e, id: month + "_" + randomUUID(), ts: Date.now(), by: me.username, byId: me.username };
      await mutate("logs/" + month, arr => { arr.push(entry); }, []);
      return send(200, entry);
    }
    const r = p.match(/^\/api\/logs\/(\d{4}-\d{2}_[\w-]+)$/);
    if (r) {
      const id = r[1], key = "logs/" + id.slice(0, 7);
      if (m === "PATCH") {
        const d = await readBody(req); let res = "nf", out;
        await mutate(key, arr => { const l = arr.find(z => z.id === id); if (!l) return false; if (me.role !== "admin" && l.byId !== me.username) { res = "forbidden"; return false; } if (d.status !== undefined) l.status = clean(d).status; out = l; }, []);
        if (res === "forbidden") return err(403, "You can only update your own entries");
        return out ? send(200, out) : err(404, "Not found");
      }
      if (m === "DELETE") {
        if (me.role !== "admin") return err(403, "Only the admin can delete entries");
        const ok = await mutate(key, arr => { const i = arr.findIndex(z => z.id === id); if (i < 0) return false; arr.splice(i, 1); }, []);
        return ok ? send(200, { ok: true }) : err(404, "Not found");
      }
    }
    return err(404, "Not found");
  } catch (e) {
    if (String(e.message).includes("SESSION_SECRET")) return err(500, "Server not set up: add SESSION_SECRET in Netlify (see README)");
    return err(500, "Server error");
  }
};
export const config = { path: "/api/*" };
