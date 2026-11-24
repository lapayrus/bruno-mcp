import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, expect, it, jest } from '@jest/globals';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

import { callTool, makeTempDir, removeTempDirs, startHttpServer, writeFiles, type TestHttpServer } from '../helpers.js';

jest.setTimeout(60_000);

const require = createRequire(import.meta.url);
const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
let client: Client;
let api: TestHttpServer;
let collectionPath: string;
let stderr = '';

beforeAll(async () => {
  const build = writeFiles(makeTempDir(), { 'package.json': '{"type":"module","version":"0.0.0"}' });
  fs.symlinkSync(path.join(projectRoot, 'node_modules'), path.join(build, 'node_modules'), 'junction');
  execFileSync(process.execPath, [require.resolve('typescript/bin/tsc'), '--project', path.join(projectRoot, 'tsconfig.json'), '--outDir', path.join(build, 'dist')]);

  api = await startHttpServer();
  collectionPath = writeFiles(makeTempDir(), {
    'bruno.json': '{"version":"1","name":"Policy fixture","type":"collection"}',
    'environments/qa.bru': `vars {\n  baseUrl: ${api.baseUrl}\n  region: west\n}\n`,
    '..rows.csv': 'row\nfirst\n',
    '-data/rows.csv': 'row\nfirst\n',
    'checks/health.bru': 'meta {\n  name: Health\n  type: http\n  seq: 1\n}\n\n' +
      'get {\n  url: {{baseUrl}}/health?token=sample-query-value\n  body: none\n  auth: none\n}\n\n' +
      'script:post-response {\n  bru.setEnvVar("region", "east");\n}\n',
    'checks/region.bru': 'meta {\n  name: Region\n  type: http\n  seq: 2\n}\n\n' +
      'get {\n  url: {{baseUrl}}/region/{{region}}\n  body: none\n  auth: none\n}\n',
    'writes/create.bru': 'meta {\n  name: Create\n  type: http\n  seq: 1\n}\n\n' +
      'post {\n  url: {{baseUrl}}/create\n  body: none\n  auth: none\n}\n'
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      path.join(build, 'dist', 'index.js'), '--collection', collectionPath,
      '--read-only', '--redact', '--verbose', '--strict-scope', '--allow-mutations-in', 'dev'
    ],
    stderr: 'pipe'
  });
  transport.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
  client = new Client({ name: 'bruno-mcp-stdio-tests', version: '0.0.0' });
  await client.connect(transport);
});

afterAll(async () => {
  await client?.close();
  await api?.close();
  removeTempDirs();
});

it('redacts request listings and omits per-run values from verbose logs', async () => {
  const listed = await callTool(client, 'list_requests', { collectionPath });
  expect(listed.isError).toBe(false);
  expect(listed.body.requests[0].url).toBe('{{baseUrl}}/health?token=<redacted>');

  const result = await callTool(client, 'execute_request', {
    collectionPath, requestPath: 'checks/health.bru', environment: 'qa', variables: { region: 'sample-override-value' }
  });
  expect(result.body.response.status).toBe(200);
  expect(stderr).toContain('spawn: node');
  expect(stderr).not.toContain('sample-override-value');
});

it('runs requests with read-only enabled and keeps their variable changes in memory', async () => {
  const tools = (await client.listTools()).tools.map(({ name }) => name);
  expect(tools).toContain('execute_request');
  expect(tools).not.toContain('set_environment_variable');

  const result = await callTool(client, 'execute_request', { collectionPath, requestPath: 'checks/health.bru', environment: 'qa' });
  expect(result.isError).toBe(false);
  expect(result.body.response.status).toBe(200);

  const environment = await callTool(client, 'get_environment', { collectionPath, name: 'qa' });
  expect(environment.isError).toBe(false);
  expect(environment.body.variables).toContainEqual(expect.objectContaining({ name: 'region', value: 'west' }));
});

it.each(['..rows.csv', '-data/rows.csv'])('accepts a scoped GET with a normalized folder path and %s', async (dataFile) => {
  const run = await callTool(client, 'run_collection', {
    collectionPath, environment: 'qa', requests: ['checks/.'], dataFile, variables: { note: 'literal {{' }
  });
  expect({ error: run.isError ? run.text : null, summary: run.body.summary }).toMatchObject({
    error: null, summary: { iterations: 1, total: 2, passed: 2 }
  });
  expect(api.hits.at(-1)).toBe('/region/east');
  const environment = await callTool(client, 'get_environment', { collectionPath, name: 'qa' });
  expect(environment.body.variables).toContainEqual(expect.objectContaining({ name: 'region', value: 'west' }));
});

it('enforces the method and data-file flags set on the CLI', async () => {
  api.reset();
  const mutation = await callTool(client, 'execute_request', {
    collectionPath, environment: 'qa', requestPath: 'writes/create.bru'
  });
  expect(mutation.isError).toBe(true);
  expect(mutation.body.error).toContain('declared-method check');

  const outside = writeFiles(makeTempDir(), { 'rows.csv': 'row\nfirst\n' });
  const run = await callTool(client, 'run_collection', {
    collectionPath, environment: 'qa', requests: ['checks'], dataFile: path.join(outside, 'rows.csv')
  });
  expect(run.isError).toBe(true);
  expect(run.body.error).toContain('Data file must be inside the collection');
  expect(api.hits).toEqual([]);
});
