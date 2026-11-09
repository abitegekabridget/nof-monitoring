// NOF Monitoring Log - Netlify Function (API).
// ACCOUNTS come from two places: (1) the USERS environment variable (permanent accounts, e.g. the admins), and
// (2) accounts the admin creates inside the app (saved in Netlify Blobs). A signed cookie keeps people logged in.
// ENTRIES are saved in Netlify Blobs. Environment variables needed: SESSION_SECRET and USERS (see README).
import { getStore } from "@netlify/blobs";
import { pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual, createHmac } from "node:crypto";

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
const envUsers = () => (process.env.USERS || "").split(/[,;\n]+/).map(s => s.trim()).filter(Boolean).map(l => {
  const [u, role, salt, hash] = l.split(":");
  return { username: (u || "").toLowerCase(), role: role === "admin" ? "admin" : "officer", salt, hash, src: "env" };
}).filter(u => u.username && /^[0-9a-f]+$/i.test(u.salt || "") && /^[0-9a-f]{64}$/i.test(u.hash || ""));
const pub = u => ({ id: u.username, username: u.username, role: u.role, mustChange: !!u.mustChange, source: u.src === "env" ? "netlify" : "app" });
const validPw = p => typeof p === "string" && p.length >= 8 && p.length <= 100;
const newHash = pw => { const salt = randomBytes(16).toString("hex"); return { salt, hash: pbk(pw, salt) }; };
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
// if Blobs is briefly unavailable, the permanent accounts (USERS setting) can still log in
const appUsers = async () => { try { return (await getJSON("users", [])).map(x => ({ ...x, src: "app" })); } catch (e) { console.error("could not read users from Blobs:", e); return []; } };
const allUsers = async () => { const e = envUsers(), names = new Set(e.map(x => x.username)); return [...e, ...(await appUsers()).filter(x => !names.has(x.username))]; };
const readBody = async req => { try { return await req.json(); } catch { return {}; } };
const MONTH = /^\d{4}-\d{2}$/;

export default async (req) => {
  const url = new URL(req.url), p = url.pathname.replace(/\/+$/, ""), m = req.method;
  try {
    if (m !== "GET" && !(req.headers.get("content-type") || "").startsWith("application/json")) return err(415, "JSON required");
    secret();
    if (p === "/api/login" && m === "POST") {
      const d = await readBody(req), un = str(d.username, 40).toLowerCase();
      const u = (await allUsers()).find(x => x.username === un);
      const ok = u ? safeEq(pbk(d.password, u.salt), u.hash) : (pbk(d.password, "00"), false);
      if (!ok) { await sleep(700); return err(401, "Wrong username or password"); }
      return send(200, pub(u), { "Set-Cookie": sessionCookie(u) });
    }
    if (p === "/api/logout" && m === "POST") return send(200, { ok: true }, { "Set-Cookie": "sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
    if (!p.startsWith("/api/")) return err(404, "Not found");

    const tok = verify(cookieOf(req, "sid"));
    const all = tok ? await allUsers() : [];
    const me = tok && all.find(x => x.username === tok.u && x.hash.slice(0, 12) === tok.h);
    if (!me) return err(401, "Please log in");

    if (p === "/api/me" && m === "GET") return send(200, pub(me));
    if (p === "/api/password" && m === "POST") {
      if (me.src === "env") return err(400, "Your password is set by the administrator in Netlify settings. Ask them to change it.");
      const d = await readBody(req);
      if (!safeEq(pbk(d.old, me.salt), me.hash)) return err(400, "Current password is wrong");
      if (!validPw(d.new)) return err(400, "New password must be at least 8 characters");
      let fresh;
      await mutate("users", arr => { const x = arr.find(z => z.username === me.username); if (!x) return false; Object.assign(x, newHash(d.new)); x.mustChange = false; fresh = { ...x, src: "app" }; }, []);
      return send(200, { ok: true }, { "Set-Cookie": sessionCookie(fresh) });
    }
    if (me.mustChange) return err(403, "Change your password first");
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
        await mutate(key, arr => {
          const l = arr.find(z => z.id === id); if (!l) return false;
          if (me.role !== "admin" && l.byId !== me.username) { res = "forbidden"; return false; }
          const c = clean({ ...l, ...d }), nx = { nof: l.nof, series: l.series, issue: l.issue, action: l.action, status: l.status };
          for (const k of ["nof", "series", "issue", "action", "status"]) if (d[k] !== undefined) nx[k] = c[k];
          if (l.type !== "issue") { nx.status = l.status; nx.action = l.action; }
          if (!nx.nof || (l.type !== "clear" && !nx.issue.trim())) { res = "empty"; return false; }
          Object.assign(l, nx);
          if (Object.keys(d).some(k => k !== "status")) { l.edited = Date.now(); l.editedBy = me.username; }
          out = l;
        }, []);
        if (res === "forbidden") return err(403, "You can only change your own entries");
        if (res === "empty") return err(400, "The issue cannot be empty");
        return out ? send(200, out) : err(404, "Not found");
      }
      if (m === "DELETE") {
        let res = "nf";
        await mutate(key, arr => {
          const i = arr.findIndex(z => z.id === id); if (i < 0) return false;
          if (me.role !== "admin" && arr[i].byId !== me.username) { res = "forbidden"; return false; }
          arr.splice(i, 1); res = "ok";
        }, []);
        if (res === "forbidden") return err(403, "You can only delete your own entries");
        return res === "ok" ? send(200, { ok: true }) : err(404, "Not found");
      }
    }
    if (p.startsWith("/api/users")) {
      if (me.role !== "admin") return err(403, "Admin only");
      if (p === "/api/users" && m === "GET") return send(200, all.map(pub));
      if (p === "/api/users" && m === "POST") {
        const d = await readBody(req), un = str(d.username, 40).toLowerCase();
        if (!/^[a-z0-9._-]{3,30}$/.test(un)) return err(400, "Username: 3-30 letters, numbers, . _ -");
        if (!validPw(d.password)) return err(400, "Password must be at least 8 characters");
        if (all.some(x => x.username === un)) return err(400, "That username already exists");
        const ok = await mutate("users", arr => { if (arr.some(x => x.username === un)) return false; arr.push({ username: un, role: d.role === "admin" ? "admin" : "officer", ...newHash(d.password), mustChange: true }); }, []);
        return ok ? send(200, { ok: true }) : err(400, "That username already exists");
      }
      const r2 = p.match(/^\/api\/users\/([a-z0-9._-]{3,30})(\/password)?$/);
      if (r2) {
        const un = r2[1], t = all.find(x => x.username === un);
        if (!t) return err(404, "Not found");
        if (t.src === "env") return err(400, "This account is set in Netlify settings (USERS). Change it there.");
        if (r2[2] && m === "POST") {
          const d = await readBody(req); if (!validPw(d.password)) return err(400, "Password must be at least 8 characters");
          await mutate("users", arr => { const x = arr.find(z => z.username === un); if (!x) return false; Object.assign(x, newHash(d.password)); x.mustChange = true; }, []);
          return send(200, { ok: true });
        }
        if (!r2[2] && m === "DELETE") {
          if (un === me.username) return err(400, "You cannot delete your own account");
          await mutate("users", arr => { const i = arr.findIndex(z => z.username === un); if (i < 0) return false; arr.splice(i, 1); }, []);
          return send(200, { ok: true });
        }
      }
    }
    return err(404, "Not found");
  } catch (e) {
    console.error("api error", m, p, e);
    if (String(e && e.message).includes("SESSION_SECRET")) return err(500, "Server not set up: add SESSION_SECRET in Netlify (see README)");
    return err(500, "Server error: " + String((e && e.message) || e).slice(0, 160));
  }
};
export const config = { path: "/api/*" };
