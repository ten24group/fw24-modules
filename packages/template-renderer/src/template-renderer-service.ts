import { createLogger, ILogger, Injectable } from '@ten24group/fw24';

import Handlebars from 'handlebars';
import fs from 'fs/promises';

export type TemplateFormat = 'html' | 'hbs' | 'text';

interface RendererConfig {
    customHelpers?: Record<string, Handlebars.HelperDelegate>; // Optional Handlebars helpers
    partials?: Record<string, Handlebars.Template>; // Optional Handlebars partials
    i18n?: (key: string, locale?: string) => string; // Optional i18n function for localization
}

export class TemplateRendererService {
    
    readonly logger: ILogger = createLogger(TemplateRendererService);
  
    constructor(private config: RendererConfig = {}) {
        if (config.customHelpers) { 
            this.registerHelpers(config.customHelpers);
        }
        if (config.partials) {
            this.registerPartials(config.partials);
        }
    }

    /**
     * Renders a template based on the provided format and data.
     */
    public async render<T>(
        template: string | { path: string },
        data: T,
        format: TemplateFormat = 'text',
        locale?: string
    ): Promise<string> {

        const templateContent = await this.getTemplateContent(template);
        const localizedData = this.applyI18n(data, locale);

        switch (format) {
            case 'html':
                return this.renderHTML(templateContent, localizedData);
            case 'hbs':
                return this.renderHBS(templateContent, localizedData);
            case 'text':
                return this.renderText(templateContent, localizedData);
            default:
            throw new Error(`Unsupported template format: ${format}`);
        }
    }

  /**
   * Fetches template content either from a file or directly as a string.
   */
    private async getTemplateContent(template: string | { path: string }): Promise<string> {
        if (typeof template === 'string') { 
            return template;
        }

        try {
            const content = await fs.readFile(template.path, 'utf-8');
            this.logger.info(`Loaded template from ${template.path}`);
            return content;
        } catch (error: any) {
            this.logger.error(`Failed to load template: ${error.message}`);
            throw error;
        }
    }

    /**
     * Renders an HTML template by interpolating data.
     */
    private renderHTML<T>(template: string, data: T): string {
        const rendered = this.interpolate(template, data);
        return rendered;
    }

    /**
     * Renders a Handlebars (HBS) template.
     */
    private renderHBS<T>(template: string, data: T): string {
        const compiledTemplate = Handlebars.compile(template);
        return compiledTemplate(data);
    }

    /**
     * Renders a plain text template.
     */
    private renderText<T>(template: string, data: T): string {
        return this.interpolate(template, data);
    }

    /**
     * Registers custom Handlebars helpers.
     */
    private registerHelpers(helpers: Record<string, Handlebars.HelperDelegate>): void {
        Object.entries(helpers).forEach(([name, fn]) => {
            Handlebars.registerHelper(name, fn);
        });
    }

    /**
     * Registers Handlebars partials.
     */
    private registerPartials(partials: Record<string,Handlebars.Template>): void {
        Object.entries(partials).forEach(([name, partial]) => {
            Handlebars.registerPartial(name, partial);
        });
    }

    /**
     * Interpolates a template with {{key}} syntax for basic string templates.
     */
    private interpolate<T>(template: string, data: T): string {
        return template.replace(/{{(.*?)}}/g, (_, key) => {
            const value = (data as any)[key.trim()];
            return value !== undefined ? value : '';
        });
    }

    /**
     * Applies i18n localization to the provided data if an i18n function is configured.
     */
    private applyI18n<T>(data: T, locale?: string): T {
        if (!this.config.i18n) { 
            return data;
        }

        const localizedData = { ...data };

        Object.keys(data as Object).forEach((key) => {
            if (typeof (data as any)[key] === 'string') {
                (localizedData as any)[key] = this.config.i18n!((data as any)[key], locale);
            }
        });

        return localizedData;
    }
}
