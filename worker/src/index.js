
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
