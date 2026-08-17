#!/usr/bin/env node

import { serveStdio } from '@modelcontextprotocol/server/stdio';

import { createServer, TARGET_PROTOCOL_VERSION } from './server.js';

const handle = serveStdio(createServer, { legacy: 'reject' });

console.error(
  `Supabase User MCP M0 compatibility probe listening on stdio (${TARGET_PROTOCOL_VERSION}, modern only).`,
);

let shuttingDown = false;

async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  console.error(`Received ${signal}; closing the MCP stdio transport.`);
  await handle.close();
}

process.once('SIGINT', () => {
  void shutdown('SIGINT');
});

process.once('SIGTERM', () => {
  void shutdown('SIGTERM');
});
