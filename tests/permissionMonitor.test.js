import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  PROBEABLE_PERMISSIONS,
  buildPermissionFindings,
  permissionProbe,
  sanitizePermissionReport,
  summarizePermissionReport,
} from '../src/content/permissionMonitor.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('permissionProbe', () => {
  it('nu aruncă niciodată și raportează toate permisiunile interogate', async () => {
    const report = await permissionProbe();
    expect(Array.isArray(report.permissions)).toBe(true);
    expect(report.permissions).toHaveLength(PROBEABLE_PERMISSIONS.length);
    for (const permission of report.permissions) {
      expect(PROBEABLE_PERMISSIONS).toContain(permission.name);
      expect(['granted', 'denied', 'prompt', 'unsupported']).toContain(permission.state);
      expect(typeof permission.supported).toBe('boolean');
    }
  });

  it('citește starea reală din navigator.permissions când este disponibil', async () => {
    vi.stubGlobal('navigator', {
      permissions: {
        query: async ({ name }) => ({ state: name === 'camera' ? 'granted' : 'prompt' }),
      },
      mediaDevices: {
        enumerateDevices: async () => [
          { kind: 'videoinput', label: 'Cameră personală NU trebuie citită' },
          { kind: 'audioinput' },
        ],
      },
    });
    vi.stubGlobal('location', { host: 'exemplu.ro', origin: 'https://exemplu.ro' });
    vi.stubGlobal('window', { isSecureContext: true });

    const report = await permissionProbe();
    expect(report.host).toBe('exemplu.ro');
    expect(report.secureContext).toBe(true);
    expect(report.permissions.find((p) => p.name === 'camera').state).toBe('granted');
    expect(report.permissions.find((p) => p.name === 'microphone').state).toBe('prompt');
    expect(report.devices.camera).toBe(1);
    expect(report.devices.microphone).toBe(1);
    // Etichetele dispozitivelor nu trebuie păstrate nicăieri în raport.
    expect(JSON.stringify(report)).not.toContain('personală');
  });
});

describe('sanitizePermissionReport', () => {
  it('respinge valorile care nu sunt obiecte', () => {
    expect(sanitizePermissionReport(null)).toBeNull();
    expect(sanitizePermissionReport('text')).toBeNull();
  });

  it('normalizează stare necunoscută și trunchiază câmpurile lungi', () => {
    const sanitized = sanitizePermissionReport({
      host: 'x'.repeat(500),
      origin: 'y'.repeat(1000),
      secureContext: 'da',
      permissions: [
        { name: 'camera'.repeat(30), state: 'necunoscut', supported: 'yes' },
        { nu: 'are nume' },
      ],
      devices: { camera: 3, microphone: -1, speaker: 99999 },
    });
    expect(sanitized.host).toHaveLength(255);
    expect(sanitized.origin).toHaveLength(512);
    expect(sanitized.secureContext).toBe(false);
    expect(sanitized.permissions).toHaveLength(1);
    expect(sanitized.permissions[0].state).toBe('unsupported');
    expect(sanitized.permissions[0].name.length).toBeLessThanOrEqual(64);
    expect(sanitized.devices).toEqual({ camera: 3, microphone: null, speaker: null });
  });
});

describe('summarizePermissionReport', () => {
  it('grupează permisiunile și adaugă explicații în română', () => {
    const summary = summarizePermissionReport({
      host: 'banca.example',
      origin: 'https://banca.example',
      secureContext: true,
      permissions: [
        { name: 'camera', state: 'granted', supported: true },
        { name: 'geolocation', state: 'prompt', supported: true },
        { name: 'usb', state: 'denied', supported: true },
        { name: 'midi', state: 'unsupported', supported: false },
      ],
      devices: { camera: 1, microphone: null, speaker: null },
    });

    expect(summary.available).toBe(true);
    expect(summary.granted.map((p) => p.name)).toEqual(['camera']);
    expect(summary.granted[0].label).toBe('Cameră');
    expect(summary.prompt.map((p) => p.name)).toEqual(['geolocation']);
    expect(summary.denied.map((p) => p.name)).toEqual(['usb']);
    expect(summary.unsupported.map((p) => p.name)).toEqual(['midi']);
    expect(summary.notes.join(' ')).toMatch(/NU înseamnă că pagina o și folosește/);
  });

  it('semnalează context non-securizat', () => {
    const summary = summarizePermissionReport({
      host: 'x.example',
      secureContext: false,
      permissions: [],
      devices: {},
    });
    expect(summary.available).toBe(true);
    expect(summary.notes.join(' ')).toMatch(/context securizat/);
  });

  it('întoarce un rezumat indisponibil pentru rapoarte lipsă', () => {
    const summary = summarizePermissionReport(null);
    expect(summary.available).toBe(false);
    expect(summary.granted).toEqual([]);
    expect(Array.isArray(summary.notes)).toBe(true);
  });
});

describe('buildPermissionFindings', () => {
  it('marchează permisiunile acordate/cerute/blocate', () => {
    const summary = summarizePermissionReport({
      host: 'x.example',
      secureContext: true,
      permissions: [
        { name: 'camera', state: 'granted', supported: true },
        { name: 'geolocation', state: 'prompt', supported: true },
        { name: 'usb', state: 'denied', supported: true },
      ],
      devices: {},
    });
    const findings = buildPermissionFindings(summary);
    expect(findings.map((f) => f.level)).toEqual(['granted', 'prompt', 'denied']);
    expect(findings[0].title).toContain('Cameră');
  });

  it('întoarce un singur mesaj informativ când raportul nu este disponibil', () => {
    const findings = buildPermissionFindings({ available: false, notes: ['motiv'] });
    expect(findings).toHaveLength(1);
    expect(findings[0].level).toBe('info');
  });
});
