import { Router, Request, Response } from 'express';
import crypto from 'crypto';

// In-memory stores — sufficient for single-instance CF deployment
const clients = new Map<string, { redirectUris: string[] }>();
const codes = new Map<string, { clientId: string; redirectUri: string; codeChallenge: string; codeChallengeMethod: string; expiresAt: number }>();
const tokens = new Set<string>();

// Static bearer token for the initial "no real auth" mode.
// Also accept any token we issued ourselves (stored in `tokens`).
const STATIC_TOKEN = process.env.MCP_STATIC_TOKEN || 'mcp-static-token';
tokens.add(STATIC_TOKEN);

export function isValidToken(token: string): boolean {
  return tokens.has(token);
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function verifyPKCE(verifier: string, challenge: string, method: string): boolean {
  if (method === 'S256') {
    const digest = crypto.createHash('sha256').update(verifier).digest();
    return base64url(digest) === challenge;
  }
  // plain (discouraged but allowed)
  return verifier === challenge;
}

export function createOAuthRouter(baseUrl: string): Router {
  const router = Router();

  // ── Metadata ────────────────────────────────────────────────────────────────
  router.get('/.well-known/oauth-authorization-server', (_req: Request, res: Response) => {
    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      registration_endpoint: `${baseUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256', 'plain'],
      token_endpoint_auth_methods_supported: ['none'],
    });
  });

  // ── Dynamic Client Registration (RFC 7591) ──────────────────────────────────
  router.post('/register', (req: Request, res: Response) => {
    const { redirect_uris } = req.body as { redirect_uris?: string[] };
    if (!redirect_uris?.length) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' });
      return;
    }
    const clientId = base64url(crypto.randomBytes(16));
    clients.set(clientId, { redirectUris: redirect_uris });
    res.status(201).json({
      client_id: clientId,
      redirect_uris,
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
  });

  // ── Authorization endpoint — auto-approves ───────────────────────────────────
  router.get('/authorize', (req: Request, res: Response) => {
    const { client_id, redirect_uri, response_type, code_challenge, code_challenge_method, state } =
      req.query as Record<string, string>;

    if (response_type !== 'code') {
      res.status(400).json({ error: 'unsupported_response_type' });
      return;
    }
    if (!code_challenge) {
      res.status(400).json({ error: 'invalid_request', error_description: 'code_challenge required (PKCE)' });
      return;
    }

    // Accept any registered client_id, OR any client_id if not registered
    // (permissive for the "no real auth" mode)
    const client = clients.get(client_id);
    if (client && !client.redirectUris.includes(redirect_uri)) {
      res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri mismatch' });
      return;
    }

    const code = base64url(crypto.randomBytes(32));
    codes.set(code, {
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method || 'S256',
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
    });

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    res.redirect(url.toString());
  });

  // ── Token endpoint ────────────────────────────────────────────────────────────
  router.post('/token', (req: Request, res: Response) => {
    const { grant_type, code, redirect_uri, code_verifier, client_id } =
      req.body as Record<string, string>;

    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    const entry = codes.get(code);
    if (!entry) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Unknown or expired code' });
      return;
    }
    codes.delete(code); // single use

    if (entry.expiresAt < Date.now()) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Code expired' });
      return;
    }
    if (entry.clientId !== client_id) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'client_id mismatch' });
      return;
    }
    if (entry.redirectUri !== redirect_uri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      return;
    }
    if (!code_verifier || !verifyPKCE(code_verifier, entry.codeChallenge, entry.codeChallengeMethod)) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      return;
    }

    const accessToken = base64url(crypto.randomBytes(32));
    tokens.add(accessToken);

    res.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600 * 24, // 24 h
    });
  });

  return router;
}
