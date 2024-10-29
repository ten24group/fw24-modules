import { AbstractFw24Module, FW24Construct, createLogger, ILogger, DIModule, LayerConstruct } from '@ten24group/fw24';
import { TemplateRendererService } from './template-renderer-service';

interface ITemplateRendererModuleConfig {
}

@DIModule({
    providers: [{
        provide: TemplateRendererService,
        useClass: TemplateRendererService,
    }],
    exports: [TemplateRendererService]
})
class TemplateRendererModule extends AbstractFw24Module {
    readonly logger: ILogger = createLogger(TemplateRendererModule);
    protected constructs: Map<string, FW24Construct>; 

    constructor( protected readonly config: ITemplateRendererModuleConfig){
        super(config);
        this.constructs = new Map();

        const chromiumLayer = new LayerConstruct([{
            layerName: 'pdf_gen_module_layer',
            sourcePath: 'node_modules/@sparticuz/',
            mode: 'PACKAGE_DIRECTORY',
        }]);

        this.constructs.set('pdf_gen_module_layer', chromiumLayer );
    }

    getBasePath(): string {
        return __dirname;
    }

    getConstructs(): Map<string, FW24Construct> {
        return new Map<string, FW24Construct>();
    }
}

export { 
    TemplateRendererModule, 
    TemplateRendererService,
    ITemplateRendererModuleConfig, 
};