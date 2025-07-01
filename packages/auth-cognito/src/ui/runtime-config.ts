import type { UIConfig } from './types';
// Local default config; serves as single source of truth for default values
import { defaultUIConfig } from '../default-ui-config';

let loadedConfig: UIConfig | null = null;

/**
 * Finds the widget script tag by filename and returns its src URL.
 */
function findWidgetScriptUrl(): string | undefined {
  if (typeof document === 'undefined') {
    return undefined;
  }
  const scripts = Array.from(document.getElementsByTagName('script'));
  for (const script of scripts) {
    if (script.src && script.src.endsWith('widget.js')) {
      return script.src;
    }
  }
  return undefined;
}

/**
 * Fetches the UI config from the deployed config.json at runtime, merging with defaults.
 */
export async function loadUIConfig(configUrlPath?: string): Promise<UIConfig> {
  if (loadedConfig) {
    return loadedConfig;
  }
  // Determine config URL: meta tag override or default to module-relative config.json
  const widgetScriptConfigUrlPath = findWidgetScriptUrl();
  const importUrl = import.meta.url;
  
  console.warn('urls', { configUrlPath, widgetScriptConfigUrlPath, importUrl });
   
  const configUrl = configUrlPath || new URL('config.json', importUrl || widgetScriptConfigUrlPath).toString();

  // Attempt to fetch remote config.json; if fails, fallback to defaults
  let raw: Partial<UIConfig> = {};
  try {
    const res = await fetch(configUrl);
    if (res.ok) {
      raw = await res.json() as Partial<UIConfig>;
    } else {
      console.warn(`Config fetch failed (${res.status}), using defaults`);
    }
  } catch (e) {
    console.warn('Unable to fetch config.json, using defaults', e);
  }
  // Merge fetched overrides with canonical defaults
  const cfg = {
    ...defaultUIConfig,
    ...raw,
    theme: { ...defaultUIConfig.theme, ...(raw.theme || {}) },
    features: { ...defaultUIConfig.features, ...(raw.features || {}) },
    i18n: { ...defaultUIConfig.i18n, ...(raw.i18n || {}) },
  } as UIConfig;
  loadedConfig = cfg;
  return cfg;
}

/**
 * Returns the loaded UI config. Must call loadUIConfig() first.
 */
export function getUIConfig(): UIConfig {
  if (!loadedConfig) {
    throw new Error('UI config not loaded. Call loadUIConfig() first.');
  }
  return loadedConfig;
}
