/**
 * Interface translations for the dashboard: English source strings, with
 * Finnish from ./i18n-fi. The language is the page's <html lang>, which the
 * server sets from the user's choice; English is the fallback for any string
 * without a translation.
 */
import fi from './i18n-fi'

export type Locale = 'en' | 'fi'

const dictionaries: Record<Exclude<Locale, 'en'>, Record<string, string>> = {
  fi
}

export function currentLocale(): Locale {
  return typeof document !== 'undefined' &&
    document.documentElement.lang === 'fi'
    ? 'fi'
    : 'en'
}

/** Translates `source`; `%{name}` placeholders are filled from `vars`. */
export function t(
  source: string,
  vars?: Record<string, string | number>
): string {
  const locale = currentLocale()
  const text =
    locale === 'en' ? source : (dictionaries[locale][source] ?? source)
  if (!vars) {
    return text
  }
  return text.replace(/%\{(\w+)\}/g, (match, name) =>
    name in vars ? String(vars[name]) : match
  )
}

/** Singular or plural form of `count`, translated. */
export function tn(
  singular: string,
  plural: string,
  count: number,
  vars?: Record<string, string | number>
): string {
  return t(count === 1 ? singular : plural, { count, ...vars })
}
