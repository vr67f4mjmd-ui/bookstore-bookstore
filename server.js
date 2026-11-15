'use strict';
/* خادم المتجر: بدون أي مكتبات خارجية. التشغيل: node server.js */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin1234';
const CONFIG = {
  storeName: process.env.STORE_NAME || 'مكتبة بيون ستور',
  whatsapp: process.env.WHATSAPP || '972597372559', // صيغة دولية بدون + أو أصفار
  currency: process.env.CURRENCY || '₪',
  announcement: process.env.ANNOUNCEMENT || 'الدفع عند الاستلام · اطلب كتبك بسهولة عبر الموقع أو واتساب',
  about: process.env.ABOUT || 'متجر إلكتروني لبيع الكتب. نوفر لكم كتباً متنوعة بأسعار مناسبة، والدفع عند الاستلام.'
};
const CATS = ['روايات', 'كتب دينية', 'علم نفس', 'تنمية بشرية', 'English Books', 'علوم', 'فلسفة', 'دراسات ادبية', 'نصوص',
  'علم اجتماع', 'تفاعلي', 'اقتصاد', 'ادب الرسائل', 'سيرة ذاتية', 'تاريخ', 'فكر معاصر', 'اطفال', 'دراسات', 'سياسة',
  'ميثولوجيا', 'تربية وأسرة', 'شعر', 'ادب سجون', 'قصص قصيرة', 'أدب مسرحي', 'مذكرات', 'إكسسوارات'];
const STATUSES = ['new', 'processing', 'delivered', 'cancelled'];

const PUB = __dirname;
const STATIC_FILES = new Set(['index.html', 'admin.html', 'logo.png', 'favicon.png']); // الملفات الوحيدة المسموح تقديمها للزوار
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

/* ---------- تخزين JSON ---------- */
const readDB = n => { try { return JSON.parse(fs.readFileSync(path.join(DATA, n), 'utf8')); } catch (e) { return []; } };
const writeDB = (n, v) => {
  const f = path.join(DATA, n), t = f + '.tmp';
  fs.writeFileSync(t, JSON.stringify(v, null, 1));
  fs.renameSync(t, f);
};

/* ---------- أدوات ---------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const send = (res, code, obj) => {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
};
function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'الطلب كبير جداً')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new HttpError(400, 'بيانات غير صالحة')); }
    });
    req.on('error', reject);
  });
}
const str = (v, min, max, msg) => {
  const s = typeof v === 'string' ? v.trim() : '';
  if (s.length < min || s.length > max) throw new HttpError(400, msg);
  return s;
};
const newId = () => 'b' + Date.now().toString(36) + crypto.randomBytes(3).toString('hex');

/* ---------- المصادقة ---------- */
const tokens = new Map(); // token -> انتهاء الصلاحية
const attempts = new Map(); // ip -> {n, reset}
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
function isAdmin(req) {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  const exp = tokens.get(t);
  if (!exp) return false;
  if (exp < Date.now()) { tokens.delete(t); return false; }
  return true;
}
function requireAdmin(req) { if (!isAdmin(req)) throw new HttpError(401, 'يلزم تسجيل الدخول'); }
function login(req, body) {
  const ip = req.socket.remoteAddress, now = Date.now();
  let a = attempts.get(ip);
  if (!a || a.reset < now) a = { n: 0, reset: now + 60000 };
  if (a.n >= 5) throw new HttpError(429, 'محاولات كثيرة. انتظر دقيقة ثم حاول مجدداً.');
  a.n++; attempts.set(ip, a);
  if (!crypto.timingSafeEqual(sha(body.password || ''), sha(ADMIN_PASSWORD))) throw new HttpError(401, 'كلمة المرور غير صحيحة.');
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, now + 12 * 3600 * 1000);
  return { token };
}

/* ---------- الصور ---------- */
function saveImage(dataUrl, id) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
  if (!m) throw new HttpError(400, 'صورة الغلاف غير صالحة.');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 2.5 * 1024 * 1024) throw new HttpError(400, 'الصورة كبيرة جداً.');
  const ok = (m[1] === 'jpeg' && buf.slice(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) ||
             (m[1] === 'png' && buf.slice(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) ||
             (m[1] === 'webp' && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP');
  if (!ok) throw new HttpError(400, 'ملف الصورة تالف أو غير مدعوم.');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const name = `${id}-${Date.now().toString(36)}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS, name), buf);
  return '/uploads/' + name;
}
function removeImage(url) {
  if (!url || !url.startsWith('/uploads/')) return;
  const f = path.join(UPLOADS, path.basename(url));
  fs.unlink(f, () => {});
}

/* ---------- الكتب ---------- */
function cleanBook(b) {
  const pages = Math.round(Number(b.pages)), price = Math.round(Number(b.price) * 100) / 100;
  if (!(pages >= 1 && pages <= 10000)) throw new HttpError(400, 'عدد الصفحات غير صحيح.');
  if (!(price >= 0 && price <= 100000)) throw new HttpError(400, 'السعر غير صحيح.');
  if (!CATS.includes(b.cat)) throw new HttpError(400, 'الفئة غير صحيحة.');
  if (b.stock === undefined || b.stock === null || b.stock === '') throw new HttpError(400, 'اكتب الكمية المتوفرة.');
  const stock = Math.round(Number(b.stock));
  if (!(stock >= 0 && stock <= 100000)) throw new HttpError(400, 'الكمية غير صحيحة.');
  const desc = typeof b.desc === 'string' ? b.desc.trim() : '';
  if (desc.length > 1500) throw new HttpError(400, 'النبذة طويلة جداً (الحد الأقصى 1500 حرف).');
  return {
    title: str(b.title, 1, 150, 'اكتب اسم الكتاب.'),
    author: str(b.author, 1, 100, 'اكتب اسم المؤلف.'),
    pages, price, cat: b.cat, best: !!b.best, stock, desc
  };
}

/* ---------- الطلبات ---------- */
function createOrder(body) {
  const books = readDB('books.json');
  const customer = {
    name: str(body.name, 3, 100, 'اكتب اسمك الكامل.'),
    phone: str(body.phone, 8, 25, 'رقم الهاتف غير صحيح.'),
    address: str(body.address, 5, 300, 'اكتب عنوان التوصيل بالتفصيل.')
  };
  if (!/^[0-9+\s-]{8,}$/.test(customer.phone)) throw new HttpError(400, 'رقم الهاتف غير صحيح.');
  const pay = body.pay === 'whatsapp' ? 'whatsapp' : 'cod';
  if (!Array.isArray(body.items) || !body.items.length || body.items.length > 50) throw new HttpError(400, 'السلة فارغة.');
  const need = new Map(); // دمج السطور المكررة لنفس الكتاب
  for (const i of body.items) {
    const qty = Math.round(Number(i.qty));
    if (!(qty >= 1 && qty <= 50)) throw new HttpError(400, 'الكمية غير صحيحة.');
    need.set(i.id, (need.get(i.id) || 0) + qty);
  }
  const items = [];
  for (const [id, qty] of need) {
    const b = books.find(x => x.id === id);
    if (!b) throw new HttpError(400, 'أحد الكتب لم يعد متوفراً. حدّث الصفحة وحاول مجدداً.');
    const have = Number(b.stock) || 0;
    if (have < qty) throw new HttpError(400, have > 0 ? `المتوفر من «${b.title}» ${have} نسخة فقط.` : `نفذت الكمية من «${b.title}».`);
    items.push({ id: b.id, title: b.title, price: b.price, qty }); // السعر دائماً من الخادم
  }
  const total = Math.round(items.reduce((s, i) => s + i.price * i.qty, 0) * 100) / 100;
  const orders = readDB('orders.json');
  const no = 1001 + orders.length;
  const order = { no, createdAt: new Date().toISOString(), status: 'new', customer, pay, items, total };
  orders.push(order);
  writeDB('orders.json', orders);
  for (const it of items) { const b = books.find(x => x.id === it.id); b.stock = (Number(b.stock) || 0) - it.qty; }
  writeDB('books.json', books);
  return { no, total };
}

/* ---------- المسارات ---------- */
async function api(req, res, p, m) {
  if (p === '/healthz') return send(res, 200, { ok: true });
  if (p === '/api/config' && m === 'GET') return send(res, 200, { ...CONFIG, cats: CATS });
  if (p === '/api/books' && m === 'GET') return send(res, 200, readDB('books.json'));
  if (p === '/api/orders' && m === 'POST') return send(res, 201, createOrder(await readBody(req)));
  if (p === '/api/login' && m === 'POST') return send(res, 200, login(req, await readBody(req)));

  /* ما بعد هذا للمدير فقط */
  requireAdmin(req);
  if (p === '/api/books' && m === 'POST') {
    const body = await readBody(req), id = newId();
    const book = { id, ...cleanBook(body), img: saveImage(body.img, id) };
    const books = readDB('books.json'); books.push(book); writeDB('books.json', books);
    return send(res, 201, book);
  }
  let mm = /^\/api\/books\/([\w-]+)$/.exec(p);
  if (mm) {
    const books = readDB('books.json'), i = books.findIndex(b => b.id === mm[1]);
    if (i < 0) throw new HttpError(404, 'الكتاب غير موجود.');
    if (m === 'PUT') {
      const body = await readBody(req), old = books[i];
      const upd = { ...old, ...cleanBook(body) };
      if (body.img) { upd.img = saveImage(body.img, old.id); removeImage(old.img); }
      books[i] = upd; writeDB('books.json', books);
      return send(res, 200, upd);
    }
    if (m === 'DELETE') {
      removeImage(books[i].img); books.splice(i, 1); writeDB('books.json', books);
      return send(res, 200, { ok: true });
    }
  }
  if (p === '/api/backup' && m === 'GET') return send(res, 200, { exportedAt: new Date().toISOString(), books: readDB('books.json'), orders: readDB('orders.json') });
  if (p === '/api/orders' && m === 'GET') return send(res, 200, readDB('orders.json').reverse());
  mm = /^\/api\/orders\/(\d+)$/.exec(p);
  if (mm && m === 'PATCH') {
    const body = await readBody(req), orders = readDB('orders.json'), o = orders.find(x => x.no === +mm[1]);
    if (!o) throw new HttpError(404, 'الطلب غير موجود.');
    if (!STATUSES.includes(body.status)) throw new HttpError(400, 'حالة غير صحيحة.');
    const prev = o.status;
    if (body.status !== prev) {
      const books = readDB('books.json');
      if (body.status === 'cancelled') {
        for (const it of o.items) { const b = books.find(x => x.id === it.id); if (b) b.stock = (Number(b.stock) || 0) + it.qty; }
        writeDB('books.json', books);
      } else if (prev === 'cancelled') {
        for (const it of o.items) { const b = books.find(x => x.id === it.id); if (b && (Number(b.stock) || 0) < it.qty) throw new HttpError(400, `لا تكفي الكمية الحالية من «${b.title}» لإعادة تفعيل الطلب.`); }
        for (const it of o.items) { const b = books.find(x => x.id === it.id); if (b) b.stock -= it.qty; }
        writeDB('books.json', books);
      }
    }
    o.status = body.status; writeDB('orders.json', orders);
    return send(res, 200, o);
  }
  throw new HttpError(404, 'غير موجود');
}

/* ---------- الملفات الثابتة ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.jpg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, p) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'غير مسموح');
  if (p === '/') p = '/index.html';
  if (p === '/admin') p = '/admin.html';
  let name;
  try { name = decodeURIComponent(p.slice(1)); } catch (e) { throw new HttpError(400, 'طلب غير صالح'); }
  const isUpload = p.startsWith('/uploads/');
  let full;
  if (isUpload) full = path.join(UPLOADS, path.basename(decodeURIComponent(p.slice(9))));
  else if (STATIC_FILES.has(name)) full = path.join(PUB, name);
  else throw new HttpError(404, 'الصفحة غير موجودة');
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) throw new HttpError(404, 'الصفحة غير موجودة');
  const ext = path.extname(full).toLowerCase();
  res.writeHead(200, {
    'Content-Type': TYPES[ext] || 'application/octet-stream',
    'Cache-Control': isUpload ? 'public, max-age=86400' : 'no-cache'
  });
  fs.createReadStream(full).pipe(res);
}

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  try {
    const u = new URL(req.url, 'http://localhost');
    if (u.pathname.startsWith('/api/')) await api(req, res, u.pathname, req.method);
    else serveStatic(req, res, u.pathname);
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    const code = e instanceof HttpError ? e.status : 500;
    if (u_isApi(req)) send(res, code, { error: e instanceof HttpError ? e.message : 'خطأ في الخادم' });
    else { res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(e instanceof HttpError ? e.message : 'خطأ في الخادم'); }
  }
}).listen(PORT, () => {
  console.log(`المتجر يعمل على http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'admin1234') console.log('تنبيه: غيّر كلمة المرور بالمتغير ADMIN_PASSWORD قبل النشر.');
});

function u_isApi(req) { return (req.url || '').startsWith('/api/'); }
