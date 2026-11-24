import { t, tn, currentLocale } from './i18n'

describe('i18n', () => {
  afterEach(() => {
    document.documentElement.lang = ''
  })

  it('returns the English source by default', () => {
    expect(currentLocale()).toBe('en')
    expect(t('Today')).toBe('Today')
  })

  it('translates to Finnish when the page language is Finnish', () => {
    document.documentElement.lang = 'fi'
    expect(currentLocale()).toBe('fi')
    expect(t('Today')).toBe('Tänään')
  })

  it('falls back to English for strings without a translation', () => {
    document.documentElement.lang = 'fi'
    expect(t('Not a translated string')).toBe('Not a translated string')
  })

  it('fills placeholders and picks plural forms', () => {
    document.documentElement.lang = 'fi'
    expect(tn('%{count} current visitor', '%{count} current visitors', 1)).toBe(
      '1 nykyinen kävijä'
    )
    expect(tn('%{count} current visitor', '%{count} current visitors', 3)).toBe(
      '3 nykyistä kävijää'
    )
  })
})
