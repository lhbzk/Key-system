
const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = env.ALLOWED_ORIGIN;

  const allowOrigin = allowedOrigin
    ? (origin === allowedOrigin ? allowedOrigin : "null")
    : "*";

  return {
    "access-control-allow-origin": allowOrigin,
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Preflight CORS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request, env)
      });
    }

    // API health check
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

  } catch (error) {
    return json({
      ok: false,
      service: "rd4x-key-api",
      database: "error",
      message: error.message
    }, 500, request, env);
  }
}
    // Key generation (not enabled yet)
    if (
      url.pathname === "/api/generate" &&
      request.method === "POST"
    ) {
      return json({
        ok: false,
        error: "KEY_GENERATION_NOT_CONFIGURED",
        message: "Key generation is not configured yet."
      }, 501, request, env);
    }

    // Key verification (not enabled yet)
    if (
      url.pathname === "/api/verify" &&
      request.method === "POST"
    ) {
      return json({
        ok: false,
        error: "KEY_VERIFICATION_NOT_CONFIGURED",
        message: "Key verification is not configured yet."
      }, 501, request, env);
    }

    return json({
      ok: false,
      error: "NOT_FOUND"
    }, 404, request, env);
  }
};
