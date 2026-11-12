// Genera el sitio estático de recogidas: lee el ERP (solo GET), cifra los datos con la clave
// de los monitores (AES-256-GCM, clave derivada con PBKDF2) y escribe dist/.
// Los datos nunca se publican en claro ni se guardan en el repositorio. Los logs solo llevan recuentos.
// Uso: BSCD_ERP_USER=… BSCD_ERP_PASS=… RECOGIDAS_CLAVE=… node build.mjs [dist]
import { webcrypto as crypto, createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const BASE = 'https://api.app.bscd.eu/erp';
const RUTAS = [/^\/alumnes$/, /^\/families$/, /^\/autoritzats\/familia\/\d+$/];
const ITERACIONES = 600000;
const MIN_ALUMNOS = 300;   // si el ERP devuelve menos, algo va mal: no se publica
const out = process.argv[2] || 'dist';
const { BSCD_ERP_USER: USER, BSCD_ERP_PASS: PASS, RECOGIDAS_CLAVE: CLAVE } = process.env;
if (!USER || !PASS || !CLAVE) throw new Error('Faltan BSCD_ERP_USER, BSCD_ERP_PASS o RECOGIDAS_CLAVE');
if (CLAVE.trim().length < 12) throw new Error('RECOGIDAS_CLAVE debe tener al menos 12 caracteres');

async function api(ruta, token, body) {
    if (body ? ruta !== '/admin/login' : !RUTAS.some(rx => rx.test(ruta))) throw new Error('Ruta no permitida: ' + ruta);
    for (let intento = 0; ; intento++) {
        try {
            const res = await fetch(BASE + ruta, {
                method: body ? 'POST' : 'GET',
                headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: token } : {}) },
                body: body ? JSON.stringify(body) : undefined,
                signal: AbortSignal.timeout(40000)
            });
            const js = await res.json().catch(() => null);
            if (!res.ok || !js || !js.result || js.result.success !== 1) throw new Error('HTTP ' + res.status);
            return js.data;
        } catch (e) {
            if (intento >= 2) throw new Error('ERP ' + ruta.replace(/\d+$/, '{id}') + ': ' + e.message);
            await new Promise(r => setTimeout(r, 3000 * (intento + 1)));
        }
    }
}

// El ERP devuelve entidades HTML dobles (&amp;eacute;) y a veces UTF-8 leído como Windows-1252 (Ã³, Ã“).
const LATIN1 = ('nbsp iexcl cent pound curren yen brvbar sect uml copy ordf laquo not shy reg macr deg plusmn sup2 sup3 acute micro para ' +
    'middot cedil sup1 ordm raquo frac14 frac12 frac34 iquest').split(' ');   // U+00A0…U+00BF
const CP1252 = { euro: '€', sbquo: '‚', fnof: 'ƒ', bdquo: '„', hellip: '…', dagger: '†', Dagger: '‡', circ: 'ˆ', permil: '‰', Scaron: 'Š',
    lsaquo: '‹', OElig: 'Œ', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”', bull: '•', ndash: '–', mdash: '—', tilde: '˜', trade: '™',
    scaron: 'š', rsaquo: '›', oelig: 'œ', Yuml: 'Ÿ' };
const ENTIDADES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", szlig: 'ß', aelig: 'æ', AElig: 'Æ', oslash: 'ø', Oslash: 'Ø', aring: 'å', Aring: 'Å', ...CP1252 };
LATIN1.forEach((n, i) => { ENTIDADES[n] = String.fromCharCode(0xa0 + i); });
const C = n => String.fromCharCode(n);
const MARCAS = { acute: C(0x301), grave: C(0x300), uml: C(0x308), circ: C(0x302), tilde: C(0x303), cedil: C(0x327) };
// Byte Windows-1252 (0x80-0x9F) de cada caracter "raro", para deshacer el UTF-8 mal leido. 0 = byte sin caracter.
const BYTE1252 = new Map([0x20ac, 0, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152, 0, 0x17d, 0,
    0, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122, 0x161, 0x203a, 0x153, 0, 0x17e, 0x178]
    .map((cp, i) => [C(cp), 0x80 + i]).filter(x => x[0] !== C(0)));
// Un byte inicial UTF-8 (C2-EF) seguido de 1 o 2 caracteres que no son ASCII ni letras latinas normales.
const RE_MOJIBAKE = new RegExp('[' + C(0xc2) + '-' + C(0xef) + '](?:[' + C(0x80) + '-' + C(0xbf) + ']|[^' + C(0) + '-' + C(0xff) + ']){1,2}', 'g');
const RE_ACENTOS = new RegExp('[' + C(0x300) + '-' + C(0x36f) + ']', 'g');
const RE_GUION_BLANDO = new RegExp(C(0xad), 'g');
function decod(t) {
    return t.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z0-9]+);/g, (m, e) => {
        if (e[0] === '#') return String.fromCodePoint(/^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
        if (ENTIDADES[e]) return ENTIDADES[e];
        const a = e.match(/^([a-zA-Z])(acute|grave|uml|circ|tilde|cedil)$/);
        return a ? (a[1] + MARCAS[a[2]]).normalize('NFC') : m;
    });
}
function txt(v) {
    if (v === null || v === undefined) return '';
    let t = decod(decod(String(v)));
    // Secuencias UTF-8 de 2 o 3 bytes leidas como Windows-1252 se devuelven a su caracter original.
    const byte = c => (c.charCodeAt(0) <= 0xff ? c.charCodeAt(0) : BYTE1252.get(c));
    t = t.replace(RE_MOJIBAKE, m => {
        const bs = [...m].map(byte);
        const n = bs[0] >= 0xe0 ? 3 : 2;
        if (bs.length < n || bs.slice(0, n).some((x, i) => x === undefined || (i > 0 && (x & 0xc0) !== 0x80))) return m;
        try { return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bs.slice(0, n))) + m.slice(n); } catch { return m; }
    });
    return t.replace(RE_GUION_BLANDO, '').replace(/\s+/g, ' ').trim();
}
const norm = t => txt(t).normalize('NFD').replace(RE_ACENTOS, '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const tel = v => { const t = txt(v); return t === '0' ? '' : t; };
const nombre = x => [x.nom, x.cognom1, x.cognom2].map(txt).filter(Boolean).join(' ');
// Solo el final del documento: basta para cotejar el DNI que enseña la persona y no expone el número entero.
const docFinal = x => { const d = (txt(x.dni) || txt(x.passaport)).replace(/[\s.-]/g, '').toUpperCase(); return d ? '···' + d.slice(-4) : ''; };

async function enLotes(items, n, fn) {
    const res = new Array(items.length);
    let i = 0;
    await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; res[k] = await fn(items[k]); } }));
    return res;
}

const hash = /^[A-Za-z0-9+/]{86}==$/.test(PASS) ? PASS : createHash('sha512').update(PASS, 'utf8').digest('base64');
const login = await api('/admin/login', null, { username: USER, password: hash });
const token = login.token;

const alumnes = ((await api('/alumnes', token)).alumnes || []).filter(a => a.estat === 'actiu');
if (alumnes.length < MIN_ALUMNOS) throw new Error('Solo ' + alumnes.length + ' alumnos activos: no se publica');
const idsFam = [...new Set(alumnes.map(a => Number(a.id_familia)))];
const auts = await enLotes(idsFam, 8, async id => (await api('/autoritzats/familia/' + id, token)).autoritzats || []);
const autPorFam = new Map(idsFam.map((id, i) => [id, auts[i]]));
const respPorFam = new Map(((await api('/families', token)).families || []).map(f => [Number(f.id), f.responsables || []]));

const familias = {};
let nAut = 0, nTut = 0;
for (const id of idsFam) {
    const a = autPorFam.get(id);
    const ids = new Set(a.map(x => x.id)), noms = new Set(a.map(x => norm(x.nom) + '|' + norm(x.cognom1)));
    // Padres/tutores: responsables de la familia que no figuran como autorizados (por id o por nombre).
    const tut = (respPorFam.get(id) || []).filter(r => !ids.has(r.id) && !noms.has(norm(r.nom) + '|' + norm(r.cognom1)));
    familias[id] = {
        t: tut.map(r => [nombre(r), tel(r.tel1) || tel(r.tel2)]),
        a: a.map(x => [nombre(x), tel(x.tel1), docFinal(x)])
    };
    nAut += a.length; nTut += tut.length;
}
const datos = {
    actualizado: new Intl.DateTimeFormat('es-ES', { timeZone: 'Europe/Madrid', dateStyle: 'short', timeStyle: 'short' }).format(new Date()),
    curso: login.curs_escolar_actual && login.curs_escolar_actual.nom,
    alumnos: alumnes.map(a => [[txt(a.cognom1), txt(a.cognom2)].filter(Boolean).join(' ') + ', ' + txt(a.nom), txt(a.curs), txt(a.classe), Number(a.id_familia)])
        .sort((x, y) => x[0].localeCompare(y[0], 'es')),
    familias
};

const b64 = u => Buffer.from(u).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(CLAVE.trim()), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERACIONES }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(datos)));

fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'datos.json'), JSON.stringify({ v: 1, it: ITERACIONES, salt: b64(salt), iv: b64(iv), ct: b64(new Uint8Array(ct)) }));
fs.copyFileSync(new URL('./index.html', import.meta.url), path.join(out, 'index.html'));
fs.writeFileSync(path.join(out, 'robots.txt'), 'User-agent: *\nDisallow: /\n');
fs.writeFileSync(path.join(out, '.nojekyll'), '');
console.log(`OK · ${alumnes.length} alumnos · ${idsFam.length} familias · ${nAut} autorizados · ${nTut} tutores · ${alumnes.filter(a => !autPorFam.get(Number(a.id_familia)).length).length} alumnos sin autorizados`);
