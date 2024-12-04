import { createLogger, ILogger, Injectable } from '@ten24group/fw24';
import puppeteer, { Page, type Browser } from 'puppeteer-core';
import chromium = require('@sparticuz/chromium');

interface RenderOptions {
  templateString: string;
  outputFormat: 'pdf' | 'png' | 'jpeg';
}

@Injectable()
export class PDFRendererService{

    readonly logger: ILogger = createLogger(PDFRendererService);
    private browser: undefined | Browser;

    async setupPage(page: Page, htmlContent: string){
        await page.setContent(htmlContent, { waitUntil: 'networkidle2' });
    };

    async getBrowser(): Promise<Browser> {

        if(this.browser){
            return this.browser;
        }

        this.logger.info(".... :trying to find chromiumExecPath: ....");

        const chromiumExecPath = await chromium.executablePath(
            process.env.AWS_EXECUTION_ENV ? '/opt/chromium/bin' : undefined
        );

        this.logger.info("FOUND: ....", { chromiumExecPath });

        const browser = await puppeteer.launch({
            args: chromium.args,
            executablePath: chromiumExecPath,
            headless: true,
            defaultViewport: chromium.defaultViewport,
        });

        this.logger.info("LAUNCHED: ....", { browser });

        return browser;
    }

    async render(options: RenderOptions): Promise<Uint8Array> {

        const browser = await this.getBrowser();

        const page = await browser.newPage();

        await this.setupPage(page, options.templateString);

        if (options.outputFormat === 'pdf') {
            return await page.pdf({
                format: 'A4',
                printBackground: true,
                margin: { top: '20px', right: '20px', bottom: '20px', left: '20px' },
            });
        }

        return await page.screenshot({
            type: options.outputFormat as 'png' | 'jpeg',
            fullPage: true,
        });
    }   
}