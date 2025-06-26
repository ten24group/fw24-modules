import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import config from './config.json';
import baseStyles from './styles.css?inline';

// Custom element to embed the Auth Widget
class AuthWidget extends HTMLElement {
  private rootEl!: HTMLDivElement;

  connectedCallback() {
    const shadow = this.attachShadow({ mode: 'open' });
    // theme variable overrides
    const varStyle = document.createElement('style');
    const theme = (config as any).theme || {};
    const colors = theme.colors || {};
    varStyle.textContent = `
      :host {
        --auth-widget-primary: ${colors.primary || '#0050EF'};
        --auth-widget-accent: ${colors.accent || '#FF4081'};
        --auth-widget-text-color: ${theme.textColor || '#333'};
        --auth-widget-error-color: ${theme.errorColor || 'red'};
      }
    `;
    shadow.appendChild(varStyle);

    // default widget styles
    const baseStyle = document.createElement('style');
    baseStyle.textContent = baseStyles;
    shadow.appendChild(baseStyle);

    // inject logo if provided
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
    root.render(<App />);
  }
}

if (!customElements.get('auth-widget')) {
  customElements.define('auth-widget', AuthWidget);
} 