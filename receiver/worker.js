const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function verify(secret, body, header) {
  if (!header || !header.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const hex = header.slice(7);
  if (!/^[0-9a-f]{64}$/.test(hex)) return false;
  const sig = Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
  return crypto.subtle.verify("HMAC", key, sig, enc.encode(body));
}

async function appJwt(appId, pem) {
  const der = Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, "")), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const claims = b64url(enc.encode(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(appId) })));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(`${head}.${claims}`));
  return `${head}.${claims}.${b64url(sig)}`;
}

export default {
  async fetch(req, env, _ctx, api = "https://api.github.com") {
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    const body = await req.text();
    if (!(await verify(env.WEBHOOK_SECRET, body, req.headers.get("x-hub-signature-256")))) {
      return new Response("bad signature", { status: 401 });
    }
    const event = req.headers.get("x-github-event");
    if (event === "ping") return new Response("pong");
    if (event !== "push") return new Response("ignored event", { status: 202 });

    const p = JSON.parse(body);
    const repo = p.repository?.name;
    const owner = p.repository?.owner?.login ?? p.repository?.owner?.name;
    if (p.ref !== `refs/heads/${p.repository?.default_branch}`) return new Response("not default branch", { status: 202 });
    if (p.deleted || !/^[0-9a-f]{40}$/.test(p.after || "")) return new Response("no commit", { status: 202 });
    if (repo === env.CENTRAL_REPO) return new Response("central repo", { status: 202 });

    const gh = (path, token, init = {}) =>
      fetch(`${api}${path}`, {
        ...init,
        headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": "nix-ci-receiver", "x-github-api-version": "2022-11-28", ...init.headers },
      });

    const jwt = await appJwt(env.APP_ID, env.APP_PRIVATE_KEY);
    const inst = await gh(`/repos/${owner}/${env.CENTRAL_REPO}/installation`, jwt);
    if (!inst.ok) return new Response(`installation lookup failed: ${inst.status}`, { status: 502 });
    const tok = await gh(`/app/installations/${(await inst.json()).id}/access_tokens`, jwt, {
      method: "POST",
      body: JSON.stringify({ repositories: [env.CENTRAL_REPO], permissions: { actions: "write" } }),
    });
    if (!tok.ok) return new Response(`token failed: ${tok.status}`, { status: 502 });
    const { token } = await tok.json();

    const d = await gh(`/repos/${owner}/${env.CENTRAL_REPO}/actions/workflows/push.yml/dispatches`, token, {
      method: "POST",
      body: JSON.stringify({ ref: "main", inputs: { repo, sha: p.after } }),
    });
    if (d.status !== 204) return new Response(`dispatch failed: ${d.status}`, { status: 502 });
    return new Response("dispatched", { status: 202 });
  },
};
