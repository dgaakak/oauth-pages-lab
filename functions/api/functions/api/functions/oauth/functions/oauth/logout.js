
import { getCookie, clearCookie } from "../../_shared/cookies.js";
import { sha256Base64url } from "../../_shared/crypto.js";

export async function onRequestPost(context) {
  const baseUrl = context.env.PUBLIC_BASE_URL;

  if (!baseUrl) {
    return new Response("Configuration error", {
      status: 500,
    });
  }

  const origin = context.request.headers.get("Origin");

  if (origin !== baseUrl) {
    return new Response("Forbidden", {
      status: 403,
      headers: {
        "Cache-Control": "no-store",
      },
    });
  }

  const sessionCookie = getCookie(
    context.request,
    "__Host-session"
  );

  if (sessionCookie) {
    const sessionHash =
      await sha256Base64url(sessionCookie);

    await context.env.DB.prepare(
      "DELETE FROM sessions WHERE id_hash = ?"
    )
      .bind(sessionHash)
      .run();
  }

  const headers = new Headers({
    "Cache-Control": "no-store",
  });

  headers.append(
    "Set-Cookie",
    clearCookie("__Host-session", "Strict")
  );

  return new Response(null, {
    status: 204,
    headers,
  });
}
