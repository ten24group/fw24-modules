import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import config from './config.json';

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

if (config.i18n?.enabled) {
  i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources,
      fallbackLng: config.i18n.defaultLocale || 'en',
      supportedLngs: config.i18n.locales || ['en'],
      interpolation: {
        escapeValue: false, // react already safes from xss
      },
    });
}

export default i18n; 