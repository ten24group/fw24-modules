import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule, LayerConstruct } from '@ten24group/fw24';
import { PDFRendererService } from './pdf-renderer-service';

interface IPDFRendererModuleConfig {
}

@DIModule({
    providers: [{
        provide: PDFRendererService,
        useClass: PDFRendererService,
    }],
    exports: [PDFRendererService]
})
class PDFRendererModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(PDFRendererModule);
    protected constructs: Map<string, FW24Construct>; 

    constructor( protected readonly config: IPDFRendererModuleConfig){
        super(config);
        this.constructs = new Map();

        const chromiumLayer = new LayerConstruct([{
            layerName: 'pdf_renderer_module_layer',
            sourcePath: 'node_modules/@sparticuz/',
            mode: 'PACKAGE_DIRECTORY',
        }]);

        this.constructs.set('pdf_renderer_module_layer', chromiumLayer );
    }

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return this.constructs;
    }
}

export { 
    PDFRendererModule, 
    PDFRendererService,
    IPDFRendererModuleConfig, 
};