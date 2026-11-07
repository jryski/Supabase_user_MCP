#!/usr/bin/env node

import {
  createNativeUserMcpRemotePilotFromEnvironment,
  listenNativeUserMcpRemotePilot,
  type NativeUserMcpRemotePilot,
} from './native-user-mcp-remote-pilot.js';

const FAILED = 'Supabase User MCP native remote pilot failed to start.\n';

let pilot: NativeUserMcpRemotePilot;
try {
  pilot = createNativeUserMcpRemotePilotFromEnvironment({
    env: process.env,
    argv: process.argv.slice(2),
  });
} catch {
  process.stderr.write(FAILED);
  process.exit(1);
}

const server = listenNativeUserMcpRemotePilot(pilot);
server.on('listening', () => {
  process.stderr.write(
    'Supabase User MCP native remote pilot listening on loopback. ' +
      'B grants are memory-only; a restart requires re-authorization.\n',
  );
});
server.on('error', () => {
  process.stderr.write(FAILED);
  process.exit(1);
});
