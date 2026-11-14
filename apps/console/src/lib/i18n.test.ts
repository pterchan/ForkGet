import { describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { formatDate, formatNumber, formatRelativeTime, localeCodes, matchLocale, resolveLocale, resources, setLocale, t } from './i18n';
import { messages } from './locales';

describe('translation resources', () => {
  it('provides every key and the same interpolation variables in every locale', () => {
    const variables = (value: string) => [...value.matchAll(/\{\{(\w+)\}\}/g)].map((match) => match[1]).sort();
    for (const [key, row] of Object.entries(messages)) {
      expect(row).toHaveLength(localeCodes.length);
      for (const translation of row) {
        expect(translation.trim(), key).not.toBe('');
        expect(variables(translation), key).toEqual(variables(row[0]));
      }
      for (const code of localeCodes) expect(resources[code].translation).toHaveProperty(key);
    }
  });

  it('contains translated sentences rather than English fallback copies', () => {
    for (const code of localeCodes.filter((code) => code !== 'en')) {
      expect(resources[code].translation.writable_description).not.toBe(resources.en.translation.writable_description);
      expect(resources[code].translation.error_network).not.toBe(resources.en.translation.error_network);
    }
  });

  it('updates the translator store and interpolates in all nine locales', async () => {
    for (const code of localeCodes) {
      await setLocale(code);
      expect(get(t)('branches')).toBe(resources[code].translation.branches);
      expect(get(t)('branch_count', { count: 7 })).toContain('7');
      expect(get(t)('branch_count', { count: 7 })).not.toContain('{{');
    }
    await setLocale('en');
  });

  it('requires named interpolation values at compile time', () => {
    const translate = get(t);
    if (false) {
      // @ts-expect-error Interpolated keys require values.
      translate('branch_count');
      // @ts-expect-error The count parameter cannot be replaced by an unrelated one.
      translate('branch_count', { time: '5 minutes' });
    }
    expect(translate('branch_count', { count: 5 })).toBe('Branches · 5');
    expect(translate('expires_in', { time: '5 minutes' })).toBe('Expires in 5 minutes');
  });
});

describe('locale selection and formatting', () => {
  it('uses explicit preference, then browser languages, then English', () => {
    expect(resolveLocale('fr', ['ja-JP'])).toBe('fr');
    expect(resolveLocale('xx', ['xx-XX', 'de-DE'])).toBe('de');
    expect(resolveLocale(null, ['xx'])).toBe('en');
    expect(matchLocale('zh-Hant-HK')).toBe('zh-TW');
    expect(matchLocale('zh-SG')).toBe('zh-CN');
    expect(matchLocale('it_IT')).toBe('it');
  });

  it('formats numbers, dates and relative time with the requested locale', () => {
    expect(formatNumber(1234.5, 'de')).toBe(new Intl.NumberFormat('de').format(1234.5));
    expect(formatDate('2026-11-12T12:00:00Z', 'ja', { timeZone: 'UTC', dateStyle: 'long' }))
      .toBe(new Intl.DateTimeFormat('ja', { timeZone: 'UTC', dateStyle: 'long' }).format(new Date('2026-11-12T12:00:00Z')));
    expect(formatRelativeTime(60000, 'fr', 0)).toBe(new Intl.RelativeTimeFormat('fr', { numeric: 'auto' }).format(1, 'minute'));
    expect(formatDate(null, 'en')).toBe('—');
    expect(formatDate('invalid', 'en')).toBe('—');
  });

  it('updates the document language and persists only the locale preference', async () => {
    const setItem = vi.fn();
    const html = { lang: 'en' };
    vi.stubGlobal('localStorage', { setItem });
    vi.stubGlobal('document', { documentElement: html });
    try {
      await setLocale('zh-TW');
      expect(html.lang).toBe('zh-TW');
      expect(setItem).toHaveBeenCalledExactlyOnceWith('forkget.locale', 'zh-TW');
      expect(get(t)('create_branch')).toBe('建立分支');
    } finally {
      vi.unstubAllGlobals();
      await setLocale('en');
    }
  });

  it('keeps locale switching functional when browser storage is blocked', async () => {
    vi.stubGlobal('localStorage', { setItem: () => { throw new Error('Storage disabled'); } });
    try {
      await setLocale('es');
      expect(get(t)('create_branch')).toBe('Crear rama');
    } finally {
      vi.unstubAllGlobals();
      await setLocale('en');
    }
  });
});
