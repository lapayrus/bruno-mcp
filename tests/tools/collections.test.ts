import fs from 'node:fs';
import path from 'node:path';

import { afterAll, afterEach, beforeAll, describe, expect, it } from '@jest/globals';
import type { Client } from '@modelcontextprotocol/sdk/client/index.js';

import { setPolicy } from '../../src/core/policy.js';
import { BRU_COLLECTION, ISOLATED_CONFIG, callTool, connectClient, copyCollection, makeTempDir, removeTempDirs, writeFiles } from '../helpers.js';

const makeWorkspace = () =>
  writeFiles(makeTempDir(), {
    'workspace.yml': 'opencollection: 1.0.0\ninfo:\n  name: Team\n  type: workspace\n\ncollections:\n  - name: Users\n    path: users\n',
    'users/bruno.json': '{ "version": "1", "name": "Users", "type": "collection" }'
  });

let client: Client;

beforeAll(async () => {
  client = await connectClient();
});

afterAll(async () => {
  await client.close();
});

afterEach(removeTempDirs);

describe('list_collections', () => {
  it('lists any workspace passed as workspacePath when the server is not scoped', async () => {
    const { isError, body } = await callTool(client, 'list_collections', { workspacePath: makeWorkspace() });

    expect(isError).toBe(false);
    expect(body.collections.map((c: any) => c.name)).toEqual(['Users']);
  });

  describe('on a server scoped with --collection/--workspace', () => {
    it('lists a configured workspace', async () => {
      const workspacePath = makeWorkspace();
      const scoped = await connectClient({ ...ISOLATED_CONFIG, explicitWorkspaces: [workspacePath] });
      try {
        const { isError, body } = await callTool(scoped, 'list_collections', { workspacePath });

        expect(isError).toBe(false);
        expect(body.collections.map((c: any) => c.name)).toEqual(['Users']);
      } finally {
        await scoped.close();
      }
    });

    it('refuses a workspace it was not configured for', async () => {
      const scoped = await connectClient({ ...ISOLATED_CONFIG, explicitCollections: [copyCollection(BRU_COLLECTION)] });
      try {
        const workspacePath = makeWorkspace();
        const { isError, body } = await callTool(scoped, 'list_collections', { workspacePath });

        expect(isError).toBe(true);
        expect(body.error).toBe(`This server is not configured for the workspace: ${workspacePath}`);
      } finally {
        await scoped.close();
      }
    });
  });
});

it('applies strict scope to workspace discovery and collection creation', async () => {
  const workspacePath = makeWorkspace();
  const outsideWorkspace = makeWorkspace();
  const outside = path.join(outsideWorkspace, 'new');
  const inside = path.join(workspacePath, 'new');
  setPolicy({ strictScope: true });
  const scoped = await connectClient({ ...ISOLATED_CONFIG, explicitWorkspaces: [workspacePath] });
  try {
    expect((await callTool(client, 'list_collections', { workspacePath: outsideWorkspace })).isError).toBe(true);
    const unknown = await callTool(client, 'list_requests', { collectionPath: outsideWorkspace });
    expect(unknown.isError).toBe(true);
    expect(unknown.body).not.toHaveProperty('collectionsInWorkspace');

    expect((await callTool(scoped, 'create_collection', { name: 'Outside', outputPath: outside })).isError).toBe(true);
    expect((await callTool(scoped, 'create_collection', { name: 'Outside', outputPath: outside, workspacePath })).isError).toBe(true);
    expect(fs.existsSync(outside)).toBe(false);

    const created = await callTool(scoped, 'create_collection', { name: 'New collection', outputPath: inside, workspacePath });
    expect(created.isError).toBe(false);
    expect((await callTool(scoped, 'list_requests', { collectionPath: inside })).body.total).toBe(0);
  } finally {
    setPolicy({});
    await scoped.close();
  }
});
