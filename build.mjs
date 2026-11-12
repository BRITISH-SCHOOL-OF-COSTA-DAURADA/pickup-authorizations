// Builds the static pickup-lookup site: reads the ERP (GET only), encrypts the data with the
// monitors' access key (AES-256-GCM, key derived with PBKDF2) and writes dist/.
// Data is never published in clear text nor stored in the repository. Logs carry counts only.
// Usage: BSCD_ERP_USER=… BSCD_ERP_PASS=… PICKUP_ACCESS_KEY=… node build.mjs [dist]
import { webcrypto as crypto, createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const BASE = 'https://api.app.bscd.eu/erp';
const ALLOWED_ROUTES = [/^\/alumnes$/, /^\/families$/, /^\/autoritzats\/familia\/\d+$/];
const ITERATIONS = 600000;
const MIN_STUDENTS = 300;   // if the ERP returns fewer, something is wrong: do not publish
const out = process.argv[2] || 'dist';
const { BSCD_ERP_USER: USER, BSCD_ERP_PASS: PASS, PICKUP_ACCESS_KEY: ACCESS_KEY } = process.env;
if (!USER || !PASS || !ACCESS_KEY) throw new Error('Missing BSCD_ERP_USER, BSCD_ERP_PASS or PICKUP_ACCESS_KEY');
if (ACCESS_KEY.trim().length < 12) throw new Error('PICKUP_ACCESS_KEY must be at least 12 characters long');

async function api(route, token, body) {
    if (body ? route !== '/admin/login' : !ALLOWED_ROUTES.some(rx => rx.test(route))) throw new Error('Route not allowed: ' + route);
    for (let attempt = 0; ; attempt++) {
        try {
            const res = await fetch(BASE + route, {
                method: body ? 'POST' : 'GET',
                headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: token } : {}) },
                body: body ? JSON.stringify(body) : undefined,
                signal: AbortSignal.timeout(40000)
            });
            const js = await res.json().catch(() => null);
            if (!res.ok || !js || !js.result || js.result.success !== 1) throw new Error('HTTP ' + res.status);
            return js.data;
        } catch (e) {
            if (attempt >= 2) throw new Error('ERP ' + route.replace(/\d+$/, '{id}') + ': ' + e.message);
            await new Promise(r => setTimeout(r, 3000 * (attempt + 1)));
        }
    }
}

// The ERP returns double-encoded HTML entities (&amp;eacute;) and sometimes UTF-8 read as Windows-1252.
const LATIN1 = ('nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para ' +
    'middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest').split(' ');   // U+00A0 to U+00BF
const CP1252 = { euro: '€', sbquo: '‚', fnof: 'ƒ', bdquo: '„', hellip: '…', dagger: '†', Dagger: '‡', circ: 'ˆ', permil: '‰', Scaron: 'Š',
    lsaquo: '‹', OElig: 'Œ', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', ndash: '–', mdash: '—', tilde: '˜', trade: '™',
    scaron: 'š', rsaquo: '›', oelig: 'œ', Yuml: 'Ÿ' };
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", szlig: 'ß', aelig: 'æ', AElig: 'Æ', oslash: 'ø', Oslash: 'Ø', aring: 'å', Aring: 'Å', ...CP1252 };
LATIN1.forEach((n, i) => { ENTITIES[n] = String.fromCharCode(0xa0 + i); });
const C = n => String.fromCharCode(n);
const MARKS = { acute: C(0x301), grave: C(0x300), uml: C(0x308), circ: C(0x302), tilde: C(0x303), cedil: C(0x327) };
// Windows-1252 byte (0x80-0x9F) for each "odd" character, to undo mis-read UTF-8. 0 = unassigned byte.
const BYTE1252 = new Map([0x20ac, 0, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0, 0x17d, 0,
    0, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0, 0x17e, 0x178]
    .map((cp, i) => [C(cp), 0x80 + i]).filter(x => x[0] !== C(0)));
// A UTF-8 lead byte (C2-EF) followed by 1 or 2 characters that are neither ASCII nor plain Latin letters.
const RE_MOJIBAKE = new RegExp('[' + C(0xc2) + '-' + C(0xef) + '](?:[' + C(0x80) + '-' + C(0xbf) + ']|[^' + C(0) + '-' + C(0xff) + ']){1,2}', 'g');
const RE_ACCENTS = new RegExp('[' + C(0x300) + '-' + C(0x36f) + ']', 'g');
const RE_SOFT_HYPHEN = new RegExp(C(0xad), 'g');
function decodeEntities(t) {
    return t.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z0-9]+);/g, (m, e) => {
        if (e[0] === '#') return String.fromCodePoint(/^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        if (ENTITIES[e]) return ENTITIES[e];
        const a = e.match(/^([a-zA-Z])(acute|grave|uml|circ|tilde|cedil)$/);
        return a ? (a[1] + MARKS[a[2]]).normalize('NFC') : m;
    });
}
function txt(v) {
    if (v === null || v === undefined) return '';
    let t = decodeEntities(decodeEntities(String(v)));
    // 2- or 3-byte UTF-8 sequences read as Windows-1252 are turned back into the original character.
    const byte = c => (c.charCodeAt(0) <= 0xff ? c.charCodeAt(0) : BYTE1252.get(c));
    t = t.replace(RE_MOJIBAKE, m => {
        const bs = [...m].map(byte);
        const n = bs[0] >= 0xe0 ? 3 : 2;
        if (bs.length < n || bs.slice(0, n).some((x, i) => x === undefined || (i > 0 && (x & 0xc0) !== 0x80))) return m;
        try { return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bs.slice(0, n))) + m.slice(n); } catch { return m; }
    });
    return t.replace(RE_SOFT_HYPHEN, '').replace(/\s+/g, ' ').trim();
}
const norm = t => txt(t).normalize('NFD').replace(RE_ACCENTS, '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const phone = v => { const t = txt(v); return t === '0' ? '' : t; };
const fullName = x => [x.nom, x.cognom1, x.cognom2].map(txt).filter(Boolean).join(' ');
// Only the end of the ID document: enough to check it against the one the person shows, without exposing the full number.
const idEnding = x => (txt(x.dni) || txt(x.passaport)).replace(/[\s.-]/g, '').toUpperCase().slice(-4);

async function inBatches(items, n, fn) {
    const res = new Array(items.length);
    let i = 0;
    await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; res[k] = await fn(items[k]); } }));
    return res;
}

// The password may already be stored as its SHA-512 base64 hash, which is what the ERP login expects.
const hash = /^[A-Za-z0-9+/]{86}==$/.test(PASS) ? PASS : createHash('sha512').update(PASS, 'utf8').digest('base64');
const login = await api('/admin/login', null, { username: USER, password: hash });
const token = login.token;

const active = ((await api('/alumnes', token)).alumnes || []).filter(a => a.estat === 'actiu');
if (active.length < MIN_STUDENTS) throw new Error('Only ' + active.length + ' active students: not publishing');
const familyIds = [...new Set(active.map(a => Number(a.id_familia)))];
const lists = await inBatches(familyIds, 8, async id => (await api('/autoritzats/familia/' + id, token)).autoritzats || []);
const authorisedByFamily = new Map(familyIds.map((id, i) => [id, lists[i]]));
const contactsByFamily = new Map(((await api('/families', token)).families || []).map(f => [Number(f.id), f.responsables || []]));

const families = {};
let nAuthorised = 0, nGuardians = 0;
for (const id of familyIds) {
    const a = authorisedByFamily.get(id);
    const ids = new Set(a.map(x => x.id)), names = new Set(a.map(x => norm(x.nom) + '|' + norm(x.cognom1)));
    // Parents/guardians: the family's contacts that are not listed as authorised (matched by id or by name).
    const guardians = (contactsByFamily.get(id) || []).filter(r => !ids.has(r.id) && !names.has(norm(r.nom) + '|' + norm(r.cognom1)));
    families[id] = {
        g: guardians.map(r => [fullName(r), phone(r.tel1) || phone(r.tel2)]),
        a: a.map(x => [fullName(x), phone(x.tel1), idEnding(x)])
    };
    nAuthorised += a.length; nGuardians += guardians.length;
}
const data = {
    updated: new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Madrid', dateStyle: 'short', timeStyle: 'short' }).format(new Date()),
    schoolYear: login.curs_escolar_actual && login.curs_escolar_actual.nom,
    students: active.map(a => [[txt(a.cognom1), txt(a.cognom2)].filter(Boolean).join(' ') + ', ' + txt(a.nom), txt(a.curs), txt(a.classe), Number(a.id_familia)])
        .sort((x, y) => x[0].localeCompare(y[0], 'es')),
    families
};

const b64 = u => Buffer.from(u).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(ACCESS_KEY.trim()), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));

fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'data.json'), JSON.stringify({ v: 1, it: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) }));
fs.copyFileSync(new URL('./index.html', import.meta.url), path.join(out, 'index.html'));
fs.writeFileSync(path.join(out, 'robots.txt'), 'User-agent: *\nDisallow: /\n');
fs.writeFileSync(path.join(out, '.nojekyll'), '');
const noAuthorised = active.filter(a => !authorisedByFamily.get(Number(a.id_familia)).length).length;
console.log(`OK · ${active.length} students · ${familyIds.length} families · ${nAuthorised} authorised · ${nGuardians} guardians · ${noAuthorised} students with no authorised person`);
