import crypto from "node:crypto";

export default async (req) => {
  const url = new URL(req.url);
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) return new Response("Falta configurar GITHUB_OAUTH_CLIENT_ID y GITHUB_OAUTH_CLIENT_SECRET en Netlify.", { status: 500 });
  const redirectUri = `${url.origin}/.netlify/functions/auth`;
  if (!url.searchParams.has("code")) {
    const state = crypto.randomBytes(24).toString("hex");
    const authorize = new URL("https://github.com/login/oauth/authorize");
    authorize.searchParams.set("client_id", clientId);
    authorize.searchParams.set("redirect_uri", redirectUri);
    authorize.searchParams.set("scope", "repo,user");
    authorize.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: { Location: authorize.toString(), "Set-Cookie": `er_oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600` } });
  }
  const cookies = Object.fromEntries((req.headers.get("cookie")||"").split(";").map(x=>x.trim().split("=" )).filter(x=>x.length===2));
  if (!cookies.er_oauth_state || cookies.er_oauth_state !== url.searchParams.get("state")) return new Response("Estado OAuth inválido. Cerrá la ventana e intentá nuevamente.", { status: 400 });
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code: url.searchParams.get("code"), redirect_uri: redirectUri }) });
  const token = await tokenResponse.json();
  if (!token.access_token) return new Response("No se pudo autorizar GitHub. Volvé al panel e intentá nuevamente.", { status: 400 });
  const payload = JSON.stringify({ token: token.access_token, provider: "github" });
  return new Response(`<!doctype html><meta charset="utf-8"><title>Autorización completada</title><p>Autorización completada. Podés cerrar esta ventana.</p><script>window.opener&&window.opener.postMessage("authorization:github:success:"+${JSON.stringify(payload)}, location.origin);window.close();</script>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": "er_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" } });
};
