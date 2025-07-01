import * as path from 'path';
import { Bucket, HttpMethods, BlockPublicAccess } from 'aws-cdk-lib/aws-s3';
import { RemovalPolicy } from 'aws-cdk-lib';
import { Distribution, ViewerProtocolPolicy, PriceClass } from 'aws-cdk-lib/aws-cloudfront';
import { S3StaticWebsiteOrigin } from 'aws-cdk-lib/aws-cloudfront-origins';
import { BucketDeployment, Source } from 'aws-cdk-lib/aws-s3-deployment';
import { Certificate } from 'aws-cdk-lib/aws-certificatemanager';
import { FW24Construct, FW24ConstructOutput, OutputType } from '@ten24group/fw24';
import { Fw24 } from '@ten24group/fw24';
import type { IAuthModuleConfig } from './interfaces';
import { CfnOutput } from 'aws-cdk-lib';

/**
 * Spins up S3 + CloudFront to host a pre-built auth widget bundle.
 */
export class AuthUIConstruct implements FW24Construct {
  readonly name = 'AuthUIConstruct';
  dependencies: string[] = [];
  readonly fw24 = Fw24.getInstance();
  mainStack!: any;
  output!: FW24ConstructOutput;

  constructor(private readonly uiConfig: NonNullable<IAuthModuleConfig[ 'ui' ]>) { }

  public async construct(): Promise<void> {
    const config = this.uiConfig;
    // Use the main CDK stack
    this.mainStack = this.fw24.getStack();

    // Create S3 bucket for static website assets
    const bucket = new Bucket(this.mainStack, 'AuthUIBucket', {
      bucketName: config.bucketName,
      websiteIndexDocument: 'index.html',
      websiteErrorDocument: 'index.html',
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true, // Delete all objects when the bucket is deleted
      publicReadAccess: true, // Make the bucket public
      blockPublicAccess: BlockPublicAccess.BLOCK_ACLS,
      cors: [
        {
          allowedOrigins: [ "*" ],
          allowedHeaders: [ "*" ],
          allowedMethods: [ HttpMethods.GET ],
        },
      ],
    });

    // Optional CloudFront access logs bucket
    const cfLogBucket = config.cloudFront?.logBucketName
      ? Bucket.fromBucketName(this.mainStack, 'AuthUILogBucket', config.cloudFront.logBucketName)
      : undefined;
    // Create CloudFront distribution for static website origin
    const distribution = new Distribution(this.mainStack, 'AuthUIDistribution', {
      defaultBehavior: {
        origin: new S3StaticWebsiteOrigin(bucket),
        viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      defaultRootObject: 'index.html',
      priceClass: config.cloudFront?.priceClass,
      logBucket: cfLogBucket,
      domainNames: config.customDomain ? [ config.customDomain.domainName ] : undefined,
      certificate: config.customDomain
        ? Certificate.fromCertificateArn(this.mainStack, 'AuthUICert', config.customDomain.certificateArn)
        : undefined,
    });

    // Validate build path
    if (!config.buildPath) {
      throw new Error('ui.buildPath must be provided to deploy the auth widget assets');
    }
    // Resolve <workspace-root>/config.buildPath
    const assetPath = path.isAbsolute(config.buildPath)
      ? config.buildPath
      : path.resolve(process.cwd(), config.buildPath);

    // Deploy static widget assets, config.json, and index.html
    new BucketDeployment(this.mainStack, 'AuthUIBucketDeployment', {
      sources: [
        Source.asset(assetPath),
        // runtime config overrides placeholder config.json
        Source.jsonData('config.json', {
          apiBaseUrl: config.apiBaseUrl,
          theme: config.theme,
          features: config.features,
          i18n: config.i18n,
        }),
      ],
      destinationBucket: bucket,
      distribution,
      distributionPaths: [ '/*' ],
    });

    // Export the widget URL via Fw24
    this.fw24.setConstructOutput(this, 'authWidgetUrl', distribution, OutputType.ENDPOINT, 'distributionDomainName');
    // Explicit CloudFormation output for widget URL
    new CfnOutput(this.mainStack, 'authWidgetUrl', {
      value: distribution.distributionDomainName,
      exportName: `${this.mainStack.stackName}-authWidgetUrl`,
    });
  }
} 