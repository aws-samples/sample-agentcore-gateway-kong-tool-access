#!/usr/bin/env node
// SPDX-License-Identifier: MIT-0
import { App, Aspects, Tags } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { ToolAccessStack } from '../lib/stack';

const app = new App();
const ctx = (k: string): string => {
  const v = app.node.tryGetContext(k);
  if (!v) throw new Error(`missing context: -c ${k}=<value> (see README)`);
  return v;
};
new ToolAccessStack(app, 'KtaToolAccess', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
  domainName: ctx('domainName'),
  hostedZoneId: ctx('hostedZoneId'),
  hostedZoneName: ctx('hostedZoneName'),
});
Tags.of(app).add('Project', 'agentcore-kong-tool-access');
Tags.of(app).add('Environment', 'dev');
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
