// اختبارات أمان Middle-Mile — بيانات اصطناعية فقط؛ الشبكة محجوبة وCSV الشيت يُحاكى محليًا.
// التشغيل: node tests/security.test.js   (playwright + chromium).  INDEX=<مسار> لاختبار نسخة أخرى.
const { chromium } = require('playwright');
const path = require('path');
const INDEX = process.env.INDEX || path.join(__dirname, '..', 'index.html');
const X = '<img src=x onerror=window.__xss=(window.__xss||0)+1>';
const ATTR = '" autofocus onfocus="window.__xss=(window.__xss||0)+1" x="';
const esc = (v) => '"' + String(v).replace(/"/g, '""') + '"';
let pass = 0, fail = 0;
const check = (n, c, extra) => { c ? pass++ : fail++; console.log((c ? 'PASS' : 'FAIL') + ' - ' + n + (c || extra === undefined ? '' : ' ' + JSON.stringify(extra))); };
const mkCsv = () => {
  const rows = [];
  for (let i = 0; i < 6; i++) rows.push(['2' + (6 - i) + '/10/2026', '', i % 2 ? X : 'فرع التجمع', i % 2 ? ATTR : 'في الطريق للفرع', '10', '12', X, ATTR, '08:00', '08:30', '', X, ATTR].map(esc).join(','));
  rows.push(['27/10/2026', '', 'فرع التجمع', 'في الطريق للفرع', '10', '12', 'عميل A&B', 'مساعد', '08:00', '08:40', '', '=HYPERLINK("http://x","c")', '+1+1'].map(esc).join(','));
  rows.push(['27/10/2026', '', 'فرع التجمع', 'في الطريق للفرع', '9', '11', 'عميل', 'مساعد', '08:00', '08:10', '', 'سائق عادي - Ali', 'نقل'].map(esc).join(','));
  return 'd,x,b,st,sh,bg,c,as,p,a,n,dr,vt\n' + rows.join('\n');
};
(async () => {
  const b = await chromium.launch({ args: ['--no-sandbox'] });
  const pg = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = []; pg.on('pageerror', (e) => errs.push(String(e).slice(0, 120)));
  const csv = mkCsv();
  await pg.route('**/*', (r) => { const u = r.request().url();
    if (u.includes('docs.google.com')) return r.fulfill({ status: 200, contentType: 'text/csv', headers: { 'access-control-allow-origin': '*' }, body: csv });
    return u.startsWith('file:') ? r.continue() : r.abort(); });
  await pg.addInitScript(() => { window.__blobs = []; const o = URL.createObjectURL; URL.createObjectURL = (b) => { window.__blobs.push(b); return o.call(URL, b); }; });
  await pg.goto('file://' + INDEX, { waitUntil: 'domcontentloaded' });
  await pg.waitForTimeout(3500);
  check('المصدر الحي المحاكى تم تحميله', (await pg.evaluate("document.getElementById('srcchip').textContent")).includes('مباشر'));
  // تفاعل: فتح القوائم وتحديد كل الخيارات (يولّد chips) + تمرير على عناصر
  await pg.evaluate(() => { document.querySelectorAll('.dd input[data-v]').forEach((c) => { if (!c.checked) c.click(); }); });
  await pg.waitForTimeout(800);
  await pg.evaluate(() => { document.querySelectorAll('label[data-t], summary, .hb, tr, button, .al').forEach((e) => { e.dispatchEvent(new MouseEvent('mouseover', { bubbles: true })); }); });
  await pg.evaluate(() => { document.querySelectorAll('[autofocus],[onfocus]').forEach((e) => e.focus && e.focus()); });
  const n = await pg.evaluate('window.__xss||0');
  check('XSS: لا تنفيذ لأي حمولة (وسوم + كسر attribute)', n === 0, n);
  check('XSS: لا عناصر img[onerror] ولا attributes onfocus في DOM', (await pg.evaluate("document.querySelectorAll('img[onerror],[onfocus]').length")) === 0);
  check('الوظيفة: عُرضت صفوف الفروع المحمّلة (الفرع الطبيعي موجود)', (await pg.evaluate("document.body.innerText.includes('فرع التجمع')")));
  check('لا أخطاء JavaScript', errs.length === 0, errs.slice(0, 2));
  // CSV
  await pg.evaluate("document.querySelector('#exportCsv, [id*=csv i], button[onclick*=exportCsv]') ? 0 : 0");
  await pg.evaluate('exportCsv()'); await pg.waitForTimeout(300);
  const out = await pg.evaluate(async () => (window.__blobs.length ? await window.__blobs[window.__blobs.length - 1].text() : ''));
  check('CSV: تم توليد الملف', out.length > 0);
  check("CSV: =HYPERLINK و +1+1 سبقهما '", out.includes("\"'=HYPERLINK(") && out.includes("'+1+1"));
  check('CSV: القيم العادية (سائق عادي - Ali) لم تتغير', out.includes('سائق عادي - Ali'));
  await b.close();
  console.log(`\n${pass}/${pass + fail} اختبارًا ناجحًا`); process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('FATAL', e.message); process.exit(2); });
