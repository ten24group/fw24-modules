import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { loadUIConfig } from './runtime-config';

// @ts-ignore: JSON import for locales
import en from './locales/en/translation.json';
// @ts-ignore: JSON import for locales
import es from './locales/es/translation.json';
// @ts-ignore: JSON import for locales
import fr from './locales/fr/translation.json';

const resources = {
  en: { translation: en },
  es: { translation: es },
  fr: { translation: fr },
};

/**
 * Initializes i18next with the runtime UI config.
 */
export async function initializeI18n(): Promise<void> {
  const cfg = await loadUIConfig();
  const i18nCfg = cfg.i18n || { enabled: false, defaultLocale: 'en', locales: ['en'] };
  if (!i18nCfg.enabled) {
    return;
  }
  await i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources,
      fallbackLng: i18nCfg.defaultLocale,
      supportedLngs: i18nCfg.locales,
      interpolation: { escapeValue: false },
    });
}

export default i18n; 