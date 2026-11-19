import http from 'node:http';
import path from 'node:path';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import { cleanupSessionTmpDir } from '../../src/core/execute.js';
import { setPolicy } from '../../src/core/policy.js';
import { createServer } from '../../src/server.js';
import { ISOLATED_CONFIG, callTool, connectClient, makeTempDir, removeTempDirs, writeFiles } from '../helpers.js';

// Each run spawns the real `bru` CLI.
jest.setTimeout(60_000);

const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
const PARENT_SECRET = 'parent-process-secret-123';

const hits: { method: string; url: string }[] = [];
let httpServer: http.Server;
let client: Client;
let collection: string;

const request = (name: string, method: string, url: string, extra = '') =>
  `meta {\n  name: ${name}\n  type: http\n  seq: 1\n}\n\n${method} {\n  url: ${url}\n  body: none\n  auth: none\n}\n${extra}`;

beforeAll(async () => {
  process.env.BRUNO_MCP_PARENT_SECRET = PARENT_SECRET;
  httpServer = http.createServer((req, res) => {
    hits.push({ method: req.method || '', url: req.url || '' });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Set-Cookie', `session=${JWT}`);
    res.end(JSON.stringify({ access_token: JWT, user: { name: 'Ada', note: `Bearer ${JWT}` }, padding: 'x'.repeat(500) }));
  });
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;

  collection = writeFiles(path.join(makeTempDir(), 'hardened'), {
    'bruno.json': JSON.stringify({ version: '1', name: 'Hardened', type: 'collection' }),
    'environments/testing.bru': `vars {\n  baseUrl: ${baseUrl}\n  accessToken: ${JWT}\n}\n`,
    'environments/production.bru': `vars {\n  baseUrl: ${baseUrl}\n}\n`,
    'auth/login.bru': request('Login', 'post', '{{baseUrl}}/login'),
    'me.bru': request('Me', 'get', '{{baseUrl}}/me?token=abc123&leak={{process.env.BRUNO_MCP_PARENT_SECRET}}'),
    '--sandbox=developer/evil.bru': request('Evil', 'get', '{{baseUrl}}/evil')
  });

  setPolicy({ readOnly: true, redact: true, maxBodyChars: 200, mutationEnvs: ['testing'], strictScope: false });
  client = await connectClient();
});

afterAll(async () => {
  setPolicy({});
  await client.close();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  cleanupSessionTmpDir();
  removeTempDirs();
});

describe('hardening policy', () => {
  it('--read-only registers no tool that writes, moves or deletes', async () => {
    const names = (await client.listTools()).tools.map((t) => t.name);
    for (const name of ['write_request', 'delete_request', 'move_request', 'create_collection', 'add_test_script',
      'remove_script', 'set_environment_variable', 'remove_environment_variable']) {
      expect(names).not.toContain(name);
    }
    expect(names).toContain('execute_request');
  });

  it('--redact keeps tokens, cookies and auth headers out of the result, and caps the body', async () => {
    const { isError, text, body } = await callTool(client, 'execute_request', {
      collectionPath: collection, requestPath: 'auth/login.bru', environment: 'testing'
    });
    expect(isError).toBe(false);
    expect(body.response.status).toBe(200);
    expect(text).not.toContain(JWT);
    expect(Object.keys(body.response.headers).map((h) => h.toLowerCase())).toEqual(['content-type']);
    expect(body.response.body).toContain('"access_token":"<redacted>"');
    expect(body.response.body).toContain('[truncated');
  });

  it('masks token query params and never passes the server env to bru', async () => {
    hits.length = 0;
    const { text } = await callTool(client, 'execute_request', {
      collectionPath: collection, requestPath: 'me.bru', environment: 'production'
    });
    expect(text).not.toContain('abc123');
    expect(hits[0].url).not.toContain(PARENT_SECRET);
  });

  it('refuses non-GET requests outside the allowed environments, before sending anything', async () => {
    hits.length = 0;
    const { isError, body } = await callTool(client, 'execute_request', {
      collectionPath: collection, requestPath: 'auth/login.bru', environment: 'production'
    });
    expect(isError).toBe(true);
    expect(body.error).toMatch(/Non-GET requests are allowed only in: testing/);
    const run = await callTool(client, 'run_collection', { collectionPath: collection, environment: 'production' });
    expect(run.isError).toBe(true);
    expect(hits).toHaveLength(0);
  });

  it('rejects argv injection through paths and {{template}} overrides', async () => {
    const evil = await callTool(client, 'execute_request', {
      collectionPath: collection, requestPath: '--sandbox=developer/evil.bru', environment: 'testing'
    });
    expect(evil.isError).toBe(true);
    expect(evil.text).toMatch(/must not start with/);
    const tmpl = await callTool(client, 'execute_request', {
      collectionPath: collection, requestPath: 'me.bru', environment: 'testing',
      variables: { baseUrl: '{{process.env.HOME}}' }
    });
    expect(tmpl.isError).toBe(true);
    expect(tmpl.text).toMatch(/literal value/);
  });

  it('--strict-scope rejects unconfigured collections and data files outside the collection', async () => {
    setPolicy({ readOnly: true, redact: true, maxBodyChars: 200, mutationEnvs: ['testing'], strictScope: true });
    try {
      // This test collection is not configured, so under strict scope it no longer resolves.
      const unscoped = await callTool(client, 'list_requests', { collectionPath: collection });
      expect(unscoped.isError).toBe(true);
    } finally {
      setPolicy({ readOnly: true, redact: true, maxBodyChars: 200, mutationEnvs: ['testing'], strictScope: false });
    }
    // A server scoped to this collection: it resolves, so the data-file confinement itself is what refuses.
    const outside = path.join(writeFiles(makeTempDir(), { 'rows.csv': 'id\n1\n' }), 'rows.csv');
    const scoped = createServer({ config: { ...ISOLATED_CONFIG, explicitCollections: [collection] } });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const scopedClient = new Client({ name: 'strict-scope-test', version: '0.0.0' });
    await Promise.all([scoped.connect(serverSide), scopedClient.connect(clientSide)]);
    setPolicy({ readOnly: true, redact: true, maxBodyChars: 200, mutationEnvs: ['testing'], strictScope: true });
    try {
      hits.length = 0;
      expect((await callTool(scopedClient, 'list_requests', { collectionPath: collection })).isError).toBe(false);
      const run = await callTool(scopedClient, 'run_collection', {
        collectionPath: collection, environment: 'testing', requests: ['me.bru'], dataFile: outside
      });
      expect(run.isError).toBe(true);
      expect(run.text).toMatch(/Data file must be inside the collection/);
      expect(hits).toHaveLength(0);
    } finally {
      setPolicy({ readOnly: true, redact: true, maxBodyChars: 200, mutationEnvs: ['testing'], strictScope: false });
      await scopedClient.close();
    }
  });

  it('get_environment hides token-named variables', async () => {
    const { text } = await callTool(client, 'get_environment', { collectionPath: collection, name: 'testing' });
    expect(text).not.toContain(JWT);
  });
});
