import { describe, expect, it } from 'vitest';

import {
  classifyIssuerTransport,
  isLoopbackHostname,
  isLoopbackHttpUrl,
  isLoopbackRedirectHostname,
  isLoopbackRedirectHttpUrl,
} from './loopback-host.js';

const hostOf = (url: string): string => new URL(url).hostname;

describe('loopback host predicates', () => {
  it('accepts localhost and canonical 127.0.0.0/8 literals', () => {
    for (const url of [
      'http://localhost/cb',
      'http://127.0.0.1/cb',
      'http://127.0.0.1:54321/cb',
      'http://127.255.255.254/cb',
      // The URL parser canonicalizes these to 127.0.0.1 before comparison.
      'http://127.1/cb',
      'http://0x7f000001/cb',
      'http://2130706433/cb',
      'http://127.0.0.1./cb',
    ]) {
      expect(isLoopbackHttpUrl(new URL(url)), url).toBe(true);
    }
  });

  it('rejects lookalike domains, userinfo tricks, IPv6 forms, and non-http schemes', () => {
    for (const url of [
      'http://127.0.0.1.evil.example/cb',
      'http://127.0.0.1.example./cb',
      'http://127.0.0.1%2eevil/cb',
      'http://127.0.0.1evil.example/cb',
      'http://evil.example/cb',
      'http://localhost.evil.example/cb',
      'http://127.0.0.1@evil.example/cb',
      'http://evil.example@127.0.0.1/cb',
      'http://user:pass@localhost/cb',
      'http://[::1]/cb',
      'http://[::ffff:127.0.0.1]/cb',
      'http://[::127.0.0.1]/cb',
      'http://128.0.0.1/cb',
      'http://10.0.0.1/cb',
      'https://127.0.0.1/cb',
      'ftp://127.0.0.1/cb',
    ]) {
      expect(isLoopbackHttpUrl(new URL(url)), url).toBe(false);
    }
  });

  it('compares the parsed hostname exactly, never by prefix', () => {
    expect(isLoopbackHostname(hostOf('http://127.0.0.1.evil.example/'))).toBe(false);
    expect(isLoopbackHostname('127.0.0.1.')).toBe(false);
    expect(isLoopbackHostname('127.0.0.256')).toBe(false);
    expect(isLoopbackHostname('127.0.0.01')).toBe(false);
    expect(isLoopbackHostname('::1')).toBe(false);
    expect(isLoopbackHostname('LOCALHOST')).toBe(false);
  });
});

describe('plaintext redirect loopback rule', () => {
  it('accepts every loopback URL plus the bracketed IPv6 loopback', () => {
    for (const url of [
      'http://localhost/cb',
      'http://127.0.0.1:8788/cb',
      'http://127.1/cb',
      'http://[::1]/cb',
      'http://[::1]:8788/cb',
      'http://[0:0:0:0:0:0:0:1]/cb',
    ]) {
      expect(isLoopbackRedirectHttpUrl(new URL(url)), url).toBe(true);
    }
    expect(isLoopbackRedirectHostname('[::1]')).toBe(true);
  });

  it('refuses lookalikes, other IPv6 forms, userinfo, and non-http schemes', () => {
    for (const url of [
      'http://127.0.0.1.evil.example/cb',
      'http://localhost.evil.example/cb',
      'http://user@[::1]/cb',
      'http://[::1]@evil.example/cb',
      'http://[::ffff:127.0.0.1]/cb',
      'http://[::127.0.0.1]/cb',
      'http://[::2]/cb',
      'https://[::1]/cb',
      'ftp://[::1]/cb',
    ]) {
      expect(isLoopbackRedirectHttpUrl(new URL(url)), url).toBe(false);
    }
    expect(isLoopbackRedirectHostname('::1')).toBe(false);
  });
});

describe('issuer transport', () => {
  it('accepts https issuers and the exact plaintext loopback issuer', () => {
    expect(classifyIssuerTransport('https://auth.example.com/auth/v1')).toBe('https');
    expect(classifyIssuerTransport('https://127.0.0.1.evil.example/auth/v1')).toBe('https');
    expect(classifyIssuerTransport('http://127.0.0.1/auth/v1')).toBe('loopback-http');
    expect(classifyIssuerTransport('http://127.0.0.1:54321/auth/v1')).toBe('loopback-http');
    expect(classifyIssuerTransport('http://127.0.0.1:54321')).toBe('loopback-http');
  });

  it('rejects lookalike, userinfo, trailing-dot, non-canonical IPv4, and IPv6 issuers', () => {
    for (const issuer of [
      'http://127.0.0.1.evil.example/auth/v1',
      'http://127.0.0.1.evil.example:54321/auth/v1',
      'http://127.0.0.1evil.example/auth/v1',
      'http://127.0.0.1%2eevil/auth/v1',
      'http://evil.example/auth/v1',
      'http://127.0.0.1@evil.example/auth/v1',
      'http://evil.example@127.0.0.1/auth/v1',
      'http://user:pass@127.0.0.1/auth/v1',
      'https://user@auth.example.com/auth/v1',
      'http://127.0.0.1./auth/v1',
      'http://127.1/auth/v1',
      'http://0x7f000001/auth/v1',
      'http://2130706433/auth/v1',
      'http://127.0.0.2/auth/v1',
      'http://localhost/auth/v1',
      'http://[::1]/auth/v1',
      'http://[::ffff:127.0.0.1]/auth/v1',
      'HTTP://127.0.0.1/auth/v1',
      'http://127.0.0.1/auth/v1?x=1',
      'http://127.0.0.1/auth/v1#f',
      'ws://127.0.0.1/auth/v1',
      'not a url',
      '',
    ]) {
      expect(classifyIssuerTransport(issuer), issuer).toBeUndefined();
    }
  });
});
