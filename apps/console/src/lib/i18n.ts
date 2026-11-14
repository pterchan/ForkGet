import { createInstance } from 'i18next';
import { derived, get, readonly, writable } from 'svelte/store';
import { localeCodes, resources, supportedLocales, type messages, type Locale, type TranslationKey } from './locales';

export { localeCodes, resources, supportedLocales };
export type { Locale, TranslationKey };
export type TranslationValues = Record<string, string | number | boolean | undefined>;
type Variables<Text extends string> = Text extends `${string}{{${infer Name}}}${infer Rest}` ? Name | Variables<Rest> : never;
type TranslationArgs<Key extends TranslationKey> = (typeof messages)[Key][0] extends `${string}{{${string}}}${string}`
  ? [values: TranslationValues & Record<Variables<(typeof messages)[Key][0]>, string | number>]
  : [values?: TranslationValues];
export type Translator = <Key extends TranslationKey>(key: Key, ...args: TranslationArgs<Key>) => string;
export const LOCALE_STORAGE_KEY = 'forkget.locale';

export function matchLocale(value: string | null | undefined): Locale | undefined {
  if (!value) return undefined;
  const normalized = value.replace(/_/g, '-').toLowerCase();
  const exact = localeCodes.find((code) => code.toLowerCase() === normalized);
  if (exact) return exact;
  if (normalized.startsWith('zh')) {
    return /(?:^|-)(?:hant|tw|hk|mo)(?:-|$)/.test(normalized) ? 'zh-TW' : 'zh-CN';
  }
  return localeCodes.find((code) => code === normalized.split('-')[0]);
}

export function resolveLocale(saved: string | null | undefined, browserLanguages: readonly string[]): Locale {
  const preferred = matchLocale(saved);
  if (preferred) return preferred;
  for (const language of browserLanguages) {
    const matched = matchLocale(language);
    if (matched) return matched;
  }
  return 'en';
}

function initialLocale(): Locale {
  let saved: string | null = null;
  try {
    if (typeof localStorage !== 'undefined') saved = localStorage.getItem(LOCALE_STORAGE_KEY);
  } catch {
    // Browser privacy settings can disable storage; language selection still works.
  }
  return resolveLocale(saved, typeof navigator === 'undefined' ? [] : navigator.languages);
}

const activeLocale = writable<Locale>(initialLocale());
export const locale = readonly(activeLocale);
const instance = createInstance();
void instance.init({
  resources,
  lng: get(activeLocale),
  fallbackLng: 'en',
  supportedLngs: [...localeCodes],
  load: 'currentOnly',
  initAsync: false,
  interpolation: { escapeValue: false },
  returnNull: false,
});

export const t = derived(activeLocale, (code): Translator => {
  const fixed = instance.getFixedT(code);
  return ((key: TranslationKey, values?: TranslationValues) => String(fixed(key, values))) as Translator;
});

function updateDocumentLanguage(code: Locale): void {
  if (typeof document !== 'undefined') document.documentElement.lang = code;
}
updateDocumentLanguage(get(activeLocale));

export async function setLocale(code: Locale): Promise<void> {
  if (!localeCodes.includes(code)) return;
  await instance.changeLanguage(code);
  activeLocale.set(code);
  updateDocumentLanguage(code);
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(LOCALE_STORAGE_KEY, code);
  } catch {
    // In-memory selection remains available when storage is blocked.
  }
}

export function formatNumber(value: number, code: Locale = get(activeLocale), options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(code, options).format(value);
}

type DateValue = string | number | Date | null | undefined;
function toDate(value: DateValue): Date | undefined {
  if (value === null || value === undefined || value === '') return undefined;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isFinite(date.getTime()) ? date : undefined;
}

export function formatDate(value: DateValue, code: Locale = get(activeLocale), options?: Intl.DateTimeFormatOptions): string {
  const date = toDate(value);
  if (!date) return '—';
  return new Intl.DateTimeFormat(code, options ?? { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export function formatRelativeTime(value: DateValue, code: Locale = get(activeLocale), now = Date.now()): string {
  const date = toDate(value);
  if (!date) return '—';
  const seconds = (date.getTime() - now) / 1000;
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60],
  ];
  const [unit, size] = units.find(([, unitSeconds]) => Math.abs(seconds) >= unitSeconds) ?? ['second', 1];
  return new Intl.RelativeTimeFormat(code, { numeric: 'auto' }).format(Math.round(seconds / size), unit);
}
