#!/usr/bin/env node

import { serveStdio } from '@modelcontextprotocol/server/stdio';

import { createServer, TARGET_PROTOCOL_VERSION } from './server.js';

const handle = serveStdio(createServer, { legacy: 'reject' });

console.error(
  `Supabase User MCP M0 compatibility probe listening on stdio (${TARGET_PROTOCOL_VERSION}, modern only).`,
);

let shuttingDown = false;
async function shutdown(): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  await handle.close();
}

process.once('SIGINT', () => {
  void shutdown();
});
process.once('SIGTERM', () => {
  void shutdown();
});
