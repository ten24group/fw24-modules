import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { loadUIConfig, getUIConfig } from './runtime-config';
import { initializeI18n } from './i18n';
import baseStyles from './styles.css?inline';
import { emitEvent, Events } from './services/event-bus';

// Custom element to embed the Auth Widget
class AuthWidget extends HTMLElement {
  private rootEl!: HTMLDivElement;

  async connectedCallback() {
    // Load runtime config and initialize translations
    await loadUIConfig();
    await initializeI18n();
    const cfg = getUIConfig();
    const shadow = this.attachShadow({ mode: 'open' });
    
    // CSS and theme injection
    const varStyle = document.createElement('style');
    const theme = (cfg.theme || {});
    const colors = theme.colors || {};
    const textColor = theme.textColor || '#333';
    const errorColor = theme.errorColor || 'red';
    varStyle.textContent = `
      :host {
        --auth-widget-primary: ${colors.primary || '#0050EF'};
        --auth-widget-accent: ${colors.accent || '#FF4081'};
        --auth-widget-text-color: ${textColor};
        --auth-widget-error-color: ${errorColor};
      }
    `;
    shadow.appendChild(varStyle);

    const baseStyle = document.createElement('style');
    baseStyle.textContent = baseStyles;
    shadow.appendChild(baseStyle);

    if (theme.customCss) {
      const customStyle = document.createElement('style');
      customStyle.textContent = theme.customCss;
      shadow.appendChild(customStyle);
    }
    
    if (theme.logoUrl) {
      const logo = document.createElement('img');
      logo.src = theme.logoUrl;
      logo.style.maxWidth = '100%';
      logo.style.display = 'block';
      logo.style.margin = '1rem auto';
      shadow.appendChild(logo);
    }

    this.rootEl = document.createElement('div');
    shadow.appendChild(this.rootEl);
    const root = ReactDOM.createRoot(this.rootEl);
    // Pass runtime config into App
    root.render(<App config={cfg} />);

    emitEvent(Events.WidgetReady);
  }
}

if (!customElements.get('auth-widget')) {
  customElements.define('auth-widget', AuthWidget);
} 