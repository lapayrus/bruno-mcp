import path from 'node:path';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';

import { cleanupSessionTmpDir } from '../../src/core/execute.js';
import {
  ISOLATED_CONFIG,
  callTool,
  connectClient,
  makeTempDir,
  removeTempDirs,
  startHttpServer,
  writeFiles,
  type TestHttpServer
} from '../helpers.js';

jest.setTimeout(60_000);

const ORDER_TOKEN = 'local-orders-token';
const orders = new Map<string, { id: string; sku: string }>();
let api: TestHttpServer;
let client: Client;
let workspacePath: string;

beforeAll(async () => {
  api = await startHttpServer(({ method, url, authorization, body }) => {
    if (method === 'POST' && url === '/graphql') {
      return { status: 200, body: { data: { product: { sku: 'SKU-RED', available: true } } } };
    }
    if (authorization !== `Bearer ${ORDER_TOKEN}`) return { status: 401, body: { error: 'Unauthorized' } };
    if (method === 'POST' && url === '/orders') {
      let input: { sku?: unknown };
      try {
        input = JSON.parse(body);
      } catch {
        return { status: 400, body: { error: 'Invalid JSON' } };
      }
      if (typeof input?.sku !== 'string' || !input.sku) return { status: 400, body: { error: 'SKU required' } };
      const order = { id: `order-${orders.size + 1}`, sku: input.sku };
      orders.set(`/orders/${order.id}`, order);
      return { status: 201, body: order };
    }
    const order = method === 'GET' && orders.get(url);
    return order ? { status: 200, body: order } : { status: 404, body: { error: 'Order not found' } };
  });
});

beforeEach(async () => {
  orders.clear();
  api.reset();
  workspacePath = writeFiles(makeTempDir(), {
    'workspace.yml': 'opencollection: 1.0.0\ninfo:\n  name: Storefront\n  type: workspace\ncollections: []\n'
  });
  client = await connectClient({ ...ISOLATED_CONFIG, explicitWorkspaces: [workspacePath] });
});

afterEach(async () => {
  await client?.close();
  removeTempDirs();
});

afterAll(async () => {
  await api?.close();
  cleanupSessionTmpDir();
});

const tool = async (name: string, args: Record<string, unknown>) => {
  const result = await callTool(client, name, args);
  expect({ tool: name, error: result.isError ? result.text : null }).toEqual({ tool: name, error: null });
  return result.body;
};

describe('Bruno project workflows', () => {
  it.each(['bru', 'yml'])('authors and runs a data-driven Orders workflow in a %s collection', async (format) => {
    const collectionPath = path.join(workspacePath, 'orders');
    const createPath = `orders/create.${format}`;
    const getPath = `orders/get.${format}`;
    const environment = 'qa';
    const auth = { mode: 'bearer', bearer: { token: '{{orderToken}}' } };

    expect(await tool('create_collection', { name: 'Orders', format, outputPath: collectionPath, workspacePath })).toMatchObject({
      registered: true, collectionPath, format
    });
    writeFiles(collectionPath, {
      [`environments/${environment}.${format}`]: format === 'bru' ? 'vars {\n}\n' : 'name: qa\nvariables: []\n',
      'orders.csv': 'sku\nSKU-RED\nSKU-BLUE\n'
    });
    await tool('set_environment_variable', { collectionPath, environment, name: 'baseUrl', value: api.baseUrl });
    await tool('set_environment_variable', { collectionPath, environment, name: 'orderToken', value: ORDER_TOKEN, secret: true });
    expect(await tool('get_environment', { collectionPath, name: environment })).toMatchObject({
      variables: expect.arrayContaining([
        expect.objectContaining({ name: 'baseUrl', value: api.baseUrl }),
        expect.objectContaining({ name: 'orderToken', value: '<redacted>', secret: true })
      ])
    });
    expect(await tool('list_environments', { collectionPath })).toMatchObject({
      environments: [{ name: environment, variableCount: 2, hasSecrets: true }]
    });

    await tool('write_request', {
      collectionPath,
      requests: [
        {
          requestPath: createPath, name: 'Create order', method: 'POST', url: '{{baseUrl}}/orders', auth,
          body: { mode: 'json', json: { sku: '{{sku}}' } }, assert: [{ name: 'res.status', value: 'eq 201' }]
        },
        {
          requestPath: getPath, name: 'Read order', method: 'GET', url: '{{baseUrl}}/orders/{{orderId}}', auth,
          assert: [{ name: 'res.status', value: 'eq 200' }]
        }
      ]
    });
    await tool('add_test_script', {
      collectionPath, requestPath: createPath, scriptType: 'post-response', script: 'bru.setVar("orderId", res.body.id);'
    });
    await tool('add_test_script', {
      collectionPath, requestPath: getPath, scriptType: 'tests',
      script: 'test("returns the order from this row", () => expect(res.body.sku).to.equal(bru.runner.iterationData.get("sku")));'
    });

    expect(await tool('list_collections', { workspacePath, search: 'Orders' })).toMatchObject({
      collections: [{ name: 'Orders', path: collectionPath, environments: [environment] }]
    });
    expect(await tool('list_folders', { collectionPath })).toMatchObject({ folders: [{ path: 'orders', requestCount: 2 }] });
    expect(await tool('get_collection_stats', { collectionPath })).toMatchObject({ requestCount: 2, byMethod: { GET: 1, POST: 1 } });
    expect(await tool('list_requests', { collectionPath, method: 'POST' })).toMatchObject({
      total: 2, requests: [{ relativePath: createPath }]
    });

    const run = await tool('run_collection', {
      collectionPath, environment, requests: ['orders'], dataFile: 'orders.csv', variables: { orderToken: ORDER_TOKEN }
    });
    expect(run.summary).toMatchObject({ iterations: 2, total: 4, passed: 4, assertions: { passed: 4 }, tests: { passed: 2 } });
    expect(api.received.map(({ method, url, body }) => [method, url, body && JSON.parse(body)])).toEqual([
      ['POST', '/orders', { sku: 'SKU-RED' }], ['GET', '/orders/order-1', ''],
      ['POST', '/orders', { sku: 'SKU-BLUE' }], ['GET', '/orders/order-2', '']
    ]);

    const denied = await callTool(client, 'execute_request', {
      collectionPath, environment, requestPath: getPath, variables: { orderId: 'order-1', orderToken: 'invalid' }
    });
    expect(denied.isError).toBe(true);
    expect(denied.body.response.status).toBe(401);

    expect(await tool('remove_environment_variable', { collectionPath, environment, name: 'orderToken' })).toMatchObject({ removed: true });
    expect(await tool('list_environments', { collectionPath })).toMatchObject({
      environments: [{ name: environment, variableCount: 1, hasSecrets: false }]
    });
  });

  it('copies a GraphQL smoke check into a YAML collection and retires the old request', async () => {
    const source = path.join(workspacePath, 'legacy-catalog');
    const target = path.join(workspacePath, 'catalog');
    await tool('create_collection', { name: 'Legacy catalog', format: 'bru', outputPath: source, workspacePath });
    await tool('create_collection', { name: 'Catalog', format: 'yml', outputPath: target, workspacePath, baseUrl: api.baseUrl });

    const query = 'query Product($sku: String!) { product(sku: $sku) { sku available } }';
    const variables = { sku: 'SKU-RED' };
    const requestPath = 'product.bru';
    await tool('write_request', {
      collectionPath: source, requestPath, url: '{{baseUrl}}/graphql',
      body: { mode: 'graphql', graphql: { query, variables: JSON.stringify(variables) } }
    });
    await tool('add_test_script', {
      collectionPath: source, requestPath, scriptType: 'tests',
      script: 'test("product is available", () => expect(res.body.data.product.available).to.equal(true));'
    });
    const moved = await tool('move_request', {
      collectionPath: source, requestPath, targetCollectionPath: target, targetFolder: 'smoke', copy: true
    });
    expect(moved.to).toBe('smoke/product.yml');
    const check = await tool('get_request', { collectionPath: target, requestPath: moved.to });
    expect(check.request).toMatchObject({ type: 'graphql-request', request: { method: 'POST', body: { mode: 'graphql' } } });

    const run = await tool('run_collection', { collectionPath: target, requests: ['smoke'] });
    expect(run.summary).toMatchObject({ total: 1, passed: 1, tests: { passed: 1 } });
    expect(api.received).toHaveLength(1);
    expect(api.received[0]).toMatchObject({ method: 'POST', url: '/graphql' });
    expect(JSON.parse(api.received[0].body)).toMatchObject({ query, variables });

    expect(await tool('remove_script', { collectionPath: target, requestPath: moved.to, scriptType: 'tests' })).toMatchObject({ removed: true });
    const updated = await tool('get_request', { collectionPath: target, requestPath: moved.to });
    expect(updated.request.request.tests || '').toBe('');
    expect(await tool('delete_request', { collectionPath: source, requestPaths: [requestPath], confirm: true })).toMatchObject({
      deletedPaths: [requestPath]
    });
    expect(await tool('list_requests', { collectionPath: source })).toMatchObject({ total: 0 });
    expect(await tool('list_requests', { collectionPath: target })).toMatchObject({ total: 1, requests: [{ relativePath: moved.to }] });
  });
});
