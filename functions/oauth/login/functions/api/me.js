import { getCookie, clearCookie } from "../../_shared/cookies.js";
import { sha256Base64url } from "../../_shared/crypto.js";

export async function onRequestGet(context) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  const sessionCookie = getCookie(
    context.request,
    "__Host-session"
  );

  if (!sessionCookie) {
    return new Response(
      JSON.stringify({ authenticated: false }),
      {
        status: 401,
        headers,
      }
    );
  }

  const sessionHash =
    await sha256Base64url(sessionCookie);

  const now =
    Math.floor(Date.now() / 1000);

  const session =
    await context.env.DB.prepare(
      `SELECT issuer, subject, email, display_name, expires_at
       FROM sessions
       WHERE id_hash = ?
         AND expires_at > ?`
    )
      .bind(sessionHash, now)
      .first();

  if (!session) {
    const responseHeaders =
      new Headers(headers);

    responseHeaders.append(
      "Set-Cookie",
      clearCookie(
        "__Host-session",
        "Strict"
      )
    );

    return new Response(
      JSON.stringify({
        authenticated: false,
      }),
      {
        status: 401,
        headers: responseHeaders,
      }
    );
  }

  return new Response(
    JSON.stringify({
      authenticated: true,
      issuer: session.issuer,
      subject: session.subject,
      email: session.email,
      name: session.display_name,
    }),
    {
      status: 200,
      headers,
    }
  );
}
