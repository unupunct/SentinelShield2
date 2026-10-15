// Avertizare pentru o descărcare cu risc ridicat, pusă în pauză de Sentinel Shield.
// Sentinel Shield NU scanează fișierul și NU dezactivează avertizările Chrome: „Reia” doar reia descărcarea, iar Chrome își aplică propriile verificări.
import { $, el, clear, send, renderIndicators, levelBadge } from '../../shared/ui.js';

const app = $('#app');
const id = new URLSearchParams(location.search).get('id');

async function load() {
  const r = await send({ type: 'ss.getDownloadWarning', id });
  clear(app);
  if (!r?.ok) { app.append(el('div', { class: 'panel' }, el('h1', { text: 'Avertizarea nu mai este disponibilă' }))); return; }
  const w = r.warning;
  const done = el('p', { 'aria-live': 'polite' });
  const indBox = el('div'); renderIndicators(indBox, w.indicators, { openFirst: true });
  app.append(
    el('div', { class: 'brandbar' }, el('b', { text: '🛡 Sentinel Shield' }), el('span', { text: 'Descărcare oprită' })),
    el('section', { class: 'hero', role: 'alert' }, levelBadge('DANGEROUS', { note: false }), el('h1', { text: 'O descărcare cu risc ridicat a fost pusă în pauză' }),
      el('div', { class: 'target' }, el('div', { class: 'small muted', text: 'Fișier' }), el('div', { class: 'host mono', text: w.extra?.filename ?? '' }), el('div', { class: 'small mono', text: `Sursă: ${w.displayUrl}` })),
      el('p', { text: w.userExplanation }), el('p', {}, el('strong', { text: 'Ce recomandăm: ' }), w.recommendation),
      el('p', { class: 'small muted', text: 'Limită: analiza se bazează pe nume, tip declarat și sursă. Conținutul fișierului nu este scanat și nu este executat niciodată.' })),
    el('div', { class: 'safe-actions' },
      el('button', { class: 'primary', id: 'cancel', autofocus: true, text: 'Anulează descărcarea', on: { click: async () => { const x = await send({ type: 'ss.downloadDecision', id, action: 'cancel' }); done.textContent = x?.ok ? 'Descărcarea a fost anulată. Poți închide această filă.' : 'Descărcarea nu mai este disponibilă.'; } } })),
    el('h2', { text: 'Motive' }), indBox,
    el('details', { class: 'continue' }, el('summary', { text: 'Reia descărcarea oricum (nerecomandat)' }),
      el('div', { class: 'box' }, el('p', { text: 'Chrome poate afișa în continuare propriile avertizări; Sentinel Shield nu le dezactivează.' }),
        el('button', { class: 'danger', text: 'Reia descărcarea', on: { click: async (e) => { if (!confirm('Sigur reiei descărcarea fișierului marcat ca riscant?')) return; const x = await send({ type: 'ss.downloadDecision', id, action: 'resume' }); done.textContent = x?.ok ? 'Descărcarea a fost reluată.' : 'Descărcarea nu mai este disponibilă.'; e.target.disabled = true; } } }))),
    done);
  $('#cancel').focus();
}
load();
