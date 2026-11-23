
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

// Comunicação com a API oficial do Linkvertise.
async function callLinkvertise(token, hash) {
  const verifyUrl = new URL(
    "https://publisher.linkvertise.com/api/v1/anti_bypassing"
  );

  verifyUrl.searchParams.set("token", token);
  verifyUrl.searchParams.set("hash", hash);

  const response = await fetch(verifyUrl.toString(), {
    method: "POST"
  });

  const text = (await response.text()).trim();

  return {
    status: response.status,
    contentType: response.headers.get("content-type") || "",
    text
  };
}

// Interpreta respostas antigas e novas do Linkvertise.
// Formatos aceitos:
// TRUE
// FALSE
// {"status":true}
// {"status":false}
function parseLinkvertiseResponse(text) {
  const value = text.trim();

  if (value === "TRUE") {
    return {
      recognized: true,
      valid: true,
      format: "TEXT"
    };
  }

  if (value === "FALSE") {
    return {
      recognized: true,
      valid: false,
      format: "TEXT"
    };
  }

  try {
    const data = JSON.parse(value);

    if (
      data &&
      typeof data.status === "boolean"
    ) {
      return {
        recognized: true,
        valid: data.status,
        format: "JSON"
      };
    }
  } catch {
    // Resposta não é JSON válido.
  }

  if (/invalid.*token|token.*invalid|authentication token/i.test(value)) {
    return {
      recognized: true,
      valid: false,
      tokenError: true,
      format: "TEXT"
    };
  }

  return {
    recognized: false,
    valid: false,
    format: "UNKNOWN"
  };
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
    if (
      url.pathname === "/api/health" &&
      request.method === "GET"
    ) {
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

        const upstream = await callLinkvertise(
          env.LINKVERTISE_TOKEN,
          hash
        );

        const snippet = upstream.text.slice(0, 120);

        // Não aceite respostas positivas com HTTP de erro.
        if (
          upstream.status < 200 ||
          upstream.status >= 300
        ) {
          console.error(JSON.stringify({
            event: "linkvertise_http_error",
            upstreamStatus: upstream.status,
            upstreamType: upstream.contentType,
            upstreamBody: snippet
          }));

          return json({
            ok: false,
            error: "LINKVERTISE_API_ERROR",
            upstreamStatus: upstream.status,
            upstream: snippet
          }, 502, request, env);
        }

        const result = parseLinkvertiseResponse(
          upstream.text
        );

        // Log seguro: nunca registra o hash completo.
        console.log(JSON.stringify({
          event: "linkvertise_verify",
          upstreamStatus: upstream.status,
          upstreamType: upstream.contentType,
          upstreamBody: snippet,
          responseFormat: result.format,
          recognized: result.recognized,
          hashLength: hash.length,
          origin: request.headers.get("Origin")
        }));

        if (!result.recognized) {
          return json({
            ok: false,
            error: "LINKVERTISE_UNEXPECTED_RESPONSE",
            upstreamStatus: upstream.status,
            upstream: snippet
          }, 502, request, env);
        }

        if (result.tokenError) {
          return json({
            ok: false,
            error: "INVALID_LINKVERTISE_TOKEN",
            upstreamStatus: upstream.status,
            upstream: snippet
          }, 403, request, env);
        }

        if (result.valid !== true) {
          return json({
            ok: false,
            error: "LINKVERTISE_HASH_NOT_FOUND_OR_EXPIRED",
            upstreamStatus: upstream.status,
            upstream: snippet
          }, 403, request, env);
        }

        // Hash confirmado pelo Linkvertise.
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + 900;
        const sessionId = crypto.randomUUID();

        const fingerprint = await hashKey(
          hash.toLowerCase()
        );

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

      } catch (error) {
        console.error("Linkvertise verification error:", error);

        return json({
          ok: false,
          error: "LINKVERTISE_VERIFICATION_ERROR"
        }, 500, request, env);
      }
    }

    // Autoteste administrativo.
    // Usa um hash fictício e não consome comprovantes reais.
    if (
      url.pathname === "/api/linkvertise/selftest" &&
      request.method === "POST"
    ) {
      if (
        !env.ADMIN_SECRET ||
        request.headers.get("Authorization") !==
          `Bearer ${env.ADMIN_SECRET}`
      ) {
        return json({
          ok: false,
          error: "UNAUTHORIZED"
        }, 401, request, env);
      }

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
        const upstream = await callLinkvertise(
          env.LINKVERTISE_TOKEN,
          "0".repeat(64)
        );

        const snippet = upstream.text.slice(0, 120);

        if (
          upstream.status < 200 ||
          upstream.status >= 300
        ) {
          return json({
            ok: false,
            error: "LINKVERTISE_API_ERROR",
            upstreamStatus: upstream.status,
            upstream: snippet
          }, 502, request, env);
        }

        const result = parseLinkvertiseResponse(
          upstream.text
        );

        let interpretation;

        if (result.tokenError) {
          interpretation = "INVALID_LINKVERTISE_TOKEN";
        } else if (
          result.recognized &&
          result.valid === false
        ) {
          interpretation =
            "API_REACHABLE_HASH_REJECTED_TOKEN_NOT_CONFIRMED";
        } else if (
          result.recognized &&
          result.valid === true
        ) {
          interpretation =
            "UNEXPECTED_SYNTHETIC_HASH_ACCEPTED";
        } else {
          interpretation = "UNKNOWN_UPSTREAM_RESPONSE";
        }

        return json({
          ok: true,
          tokenConfigured: true,
          tokenLength: env.LINKVERTISE_TOKEN.length,
          upstreamStatus: upstream.status,
          upstreamType: upstream.contentType,
          upstream: snippet,
          responseFormat: result.format,
          interpretation
        }, 200, request, env);

      } catch (error) {
        console.error("Linkvertise selftest error:", error);

        return json({
          ok: false,
          error: "SELFTEST_FAILED"
        }, 500, request, env);
      }
    }

    // Generate key - ADMIN ONLY
    if (
      url.pathname === "/api/generate" &&
      request.method === "POST"
    ) {
      if (!env.ADMIN_SECRET) {
        return json({
          ok: false,
          error: "ADMIN_SECRET_NOT_CONFIGURED"
        }, 503, request, env);
      }

      const authorization = request.headers.get("Authorization");

      if (
        authorization !== `Bearer ${env.ADMIN_SECRET}`
      ) {
        return json({
          ok: false,
          error: "UNAUTHORIZED"
        }, 401, request, env);
      }

      try {
        const body = await request.json();

        const provider = body.provider;
        const allowedProviders = [
          "lootlabs",
          "linkvertise"
        ];

        if (!allowedProviders.includes(provider)) {
          return json({
            ok: false,
            error: "INVALID_PROVIDER"
          }, 400, request, env);
        }

        const requestedTTL = Number(
          body.expiresInSeconds || 86400
        );

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
    if (
      url.pathname === "/api/verify" &&
      request.method === "POST"
    ) {
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
          
