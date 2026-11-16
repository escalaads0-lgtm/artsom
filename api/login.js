// Confere e-mail e senha (guardados como variáveis de ambiente na Vercel)
// e cria um cookie de sessão assinado, válido por 7 dias.
const enc = new TextEncoder();

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{2}/g).map((h) => parseInt(h, 16)));
}

function toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

async function pbkdf2Hex(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: 100000, hash: 'SHA-256' },
    key,
    256
  );
  return toHex(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sign(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

function redirect(location, cookie) {
  const headers = { Location: location };
  if (cookie) headers['Set-Cookie'] = cookie;
  return new Response(null, { status: 303, headers });
}

export async function POST(request) {
  const form = await request.formData();
  const email = String(form.get('email') || '').trim().toLowerCase();
  const password = String(form.get('password') || '');

  const expectedEmail = String(process.env.AUTH_EMAIL || '').trim().toLowerCase();
  const [saltHex, hashHex] = String(process.env.AUTH_PASSWORD_HASH || '').split(':');
  const secret = process.env.SESSION_SECRET;

  let ok = false;
  if (expectedEmail && saltHex && hashHex && secret && password) {
    const hash = await pbkdf2Hex(password, saltHex);
    ok = safeEqual(email, expectedEmail) && safeEqual(hash, hashHex);
  }

  if (!ok) {
    await new Promise((r) => setTimeout(r, 600));
    return redirect('/login?erro=1');
  }

  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const token = exp + '.' + (await sign(secret, 'artsom:' + exp));
  return redirect('/', `artsom_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`);
}

export function GET() {
  return redirect('/login');
}
