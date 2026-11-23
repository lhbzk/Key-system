
const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = env.ALLOWED_ORIGIN;

  return {
    "access-control-allow-origin": allowedOrigin
      ? (origin === allowedOrigin ? allowedOrigin : "null")
      : "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "Content-Type, Authorization",
    "vary": "Origin"
  };
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...corsHeaders(request, env)
    }
  });
}

async function hashKey(key) {
  const data = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

function generateKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));

  const hex = Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();

  return `RD4X-${hex.match(/.{1,8}/g).join("-")}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request, env)
      });
    }

    // Health check
    if (url.pathname === "/api/health" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();

        return json({
          ok: true,
          service: "rd4x-key-api",
          database: "connected"
        }, 200, request, env);
      } catch {
        return json({
          ok: false,
          database: "error"
        }, 500, request, env);
      }
    }

    // Linkvertise Anti-Bypass
    if (
      url.pathname === "/api/linkvertise/verify" &&
      request.method === "POST"
    ) {
      if (!env.LINKVERTISE_TOKEN) {
        return json({
          ok: false,
          error: "LINKVERTISE_TOKEN_NOT_CONFIGURED"
        }, 503, request, env);
      }

      if (
  typeof env.LINKVERTISE_TOKEN !== "string" ||
  env.LINKVERTISE_TOKEN.length !== 64
) {
  return json({
    ok: false,
    error: "INVALID_LINKVERTISE_TOKEN_CONFIGURATION"
  }, 503, request, env);
      }

      try {
        const body = await request.json();
        const hash = body.hash;

        if (
  typeof hash !== "string" ||
  hash.length !== 64
) {
          return json({
            ok: false,
            error: "INVALID_LINKVERTISE_HASH"
          }, 400, request, env);
        }

        const verifyUrl = new URL(
          "https://publisher.linkvertise.com/api/v1/anti_bypassing"
        );

        verifyUrl.searchParams.set("token", env.LINKVERTISE_TOKEN);
        verifyUrl.searchParams.set("hash", hash);

        const response = await fetch(verifyUrl.toString(), {
          method: "POST"
        });

        if (!response.ok) {
          return json({
            ok: false,
            error: "LINKVERTISE_API_ERROR"
          }, 502, request, env);
        }

        const result = (await response.text()).trim();

        if (result === "Invalid token.") {
  return json({
    ok: false,
    error: "INVALID_LINKVERTISE_TOKEN"
  }, 403, request, env);
}

if (result !== "TRUE") {
  return json({
    ok: false,
    error: "LINKVERTISE_HASH_NOT_FOUND_OR_EXPIRED"
  }, 403, request, env);
}
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + 900;
        const sessionId = crypto.randomUUID();
        const fingerprint = await hashKey(hash.toLowerCase());

        await env.DB.prepare(`
          INSERT INTO verification_sessions (
            id,
            provider,
            status,
            external_transaction_id,
            created_at,
            expires_at,
            completed_at
          )
          VALUES (?, 'linkvertise', 'completed', ?, ?, ?, ?)
        `).bind(
          sessionId,
          fingerprint,
          now,
          expiresAt,
          now
        ).run();

        return json({
          ok: true,
          verified: true,
          sessionId,
          expiresAt
        }, 200, request, env);

      } catch {
        return json({
          ok: false,
          error: "LINKVERTISE_VERIFICATION_ERROR"
        }, 500, request, env);
      }
    }

    // Generate key - ADMIN ONLY
    if (url.pathname === "/api/generate" && request.method === "POST") {
      if (!env.ADMIN_SECRET) {
        return json({
          ok: false,
          error: "ADMIN_SECRET_NOT_CONFIGURED"
        }, 503, request, env);
      }

      const authorization = request.headers.get("Authorization");

      if (authorization !== `Bearer ${env.ADMIN_SECRET}`) {
        return json({
          ok: false,
          error: "UNAUTHORIZED"
        }, 401, request, env);
      }

      try {
        const body = await request.json();

        const provider = body.provider;
        const allowedProviders = ["lootlabs", "linkvertise"];

        if (!allowedProviders.includes(provider)) {
          return json({
            ok: false,
            error: "INVALID_PROVIDER"
          }, 400, request, env);
        }

        const requestedTTL = Number(body.expiresInSeconds || 86400);

        if (
          !Number.isInteger(requestedTTL) ||
          requestedTTL < 60 ||
          requestedTTL > 2592000
        ) {
          return json({
            ok: false,
            error: "INVALID_EXPIRATION"
          }, 400, request, env);
        }

        const key = generateKey();
        const keyHash = await hashKey(key);
        const id = crypto.randomUUID();

        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + requestedTTL;

        await env.DB.prepare(`
          INSERT INTO keys (
            id,
            key_hash,
            provider,
            status,
            created_at,
            expires_at
          )
          VALUES (?, ?, ?, 'active', ?, ?)
        `).bind(
          id,
          keyHash,
          provider,
          now,
          expiresAt
        ).run();

        return json({
          ok: true,
          key,
          provider,
          expiresAt
        }, 201, request, env);

      } catch (error) {
        return json({
          ok: false,
          error: "GENERATION_FAILED",
          message: error.message
        }, 500, request, env);
      }
    }

    // Verify key
    if (url.pathname === "/api/verify" && request.method === "POST") {
      try {
        const body = await request.json();

        if (
          typeof body.key !== "string" ||
          body.key.length > 100
        ) {
          return json({
            ok: false,
            error: "INVALID_KEY"
          }, 400, request, env);
        }

        const key = body.key.trim().toUpperCase();
        const keyHash = await hashKey(key);

        const record = await env.DB.prepare(`
          SELECT provider, status, expires_at
          FROM keys
          WHERE key_hash = ?
        `).bind(keyHash).first();

        if (!record) {
          return json({
            ok: true,
            valid: false,
            reason: "KEY_NOT_FOUND"
          }, 200, request, env);
        }

        const now = Math.floor(Date.now() / 1000);

        if (record.status !== "active") {
          return json({
            ok: true,
            valid: false,
            reason: "KEY_INACTIVE"
          }, 200, request, env);
        }

        if (record.expires_at <= now) {
          await env.DB.prepare(`
            UPDATE keys
            SET status = 'expired'
            WHERE key_hash = ?
          `).bind(keyHash).run();

          return json({
            ok: true,
            valid: false,
            reason: "KEY_EXPIRED"
          }, 200, request, env);
        }

        return json({
          ok: true,
          valid: true,
          provider: record.provider,
          expiresAt: record.expires_at
        }, 200, request, env);

      } catch (error) {
        return json({
          ok: false,
          error: "VERIFICATION_FAILED",
          message: error.message
        }, 500, request, env);
      }
    }

    return json({
      ok: false,
      error: "NOT_FOUND"
    }, 404, request, env);
  }
};
            
