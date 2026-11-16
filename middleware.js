// Protege todas as páginas: sem sessão válida, redireciona para /login.
export const config = {
  matcher: ['/((?!login|api/|favicon).*)'],
};

const enc = new TextEncoder();

function b64url(buf) {
  let s = '';
  new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sign(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

async function isValid(token) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || !token) return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const expected = await sign(secret, 'artsom:' + exp);
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

export default async function middleware(request) {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/(?:^|;\s*)artsom_session=([^;]+)/);
  if (match && (await isValid(decodeURIComponent(match[1])))) return;
  return Response.redirect(new URL('/login', request.url), 302);
}
