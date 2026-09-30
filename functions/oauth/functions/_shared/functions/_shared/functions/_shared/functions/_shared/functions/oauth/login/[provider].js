import {
  randomBase64url,
  sha256Base64url,
} from "../../_shared/crypto.js";

import { getProvider } from "../../_shared/providers.js";
import { setCookie } from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const providerName =
    context.params.provider;

  const provider =
    getProvider(providerName);

  if (!provider) {
    return new Response("Not Found", {
      status: 404,
    });
  }

  const env = context.env;
  const baseUrl =
    env.PUBLIC_BASE_URL;

  if (!baseUrl) {
    return new Response(
      "Configuration error",
      { status: 500 }
    );
  }

  const state =
    randomBase64url();

  const codeVerifier =
    randomBase64url();

  const oauthCookie =
    randomBase64url();

  const stateHash =
    await sha256Base64url(state);

  const cookieHash =
    await sha256Base64url(oauthCookie);

  const codeChallenge =
    await sha256Base64url(codeVerifier);

  const nonce =
    providerName === "google"
      ? randomBase64url()
      : null;

  const expiresAt =
    Math.floor(Date.now() / 1000) + 600;

  await env.DB.prepare(
    `INSERT INTO oauth_transactions
      (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(
      cookieHash,
      providerName,
      stateHash,
      nonce,
      codeVerifier,
      expiresAt
    )
    .run();

  const redirectUri =
    `${baseUrl}/oauth/callback/${providerName}`;

  const authorizationUrl =
    new URL(
      provider.authorizationEndpoint
    );

  authorizationUrl.searchParams.set(
    "client_id",
    env[provider.clientIdEnv]
  );

  authorizationUrl.searchParams.set(
    "redirect_uri",
    redirectUri
  );

  authorizationUrl.searchParams.set(
    "response_type",
    "code"
  );

  authorizationUrl.searchParams.set(
    "state",
    state
  );

  authorizationUrl.searchParams.set(
    "code_challenge",
    codeChallenge
  );

  authorizationUrl.searchParams.set(
    "code_challenge_method",
    "S256"
  );

  if (providerName === "google") {
    authorizationUrl.searchParams.set(
      "scope",
      "openid email profile"
    );

    authorizationUrl.searchParams.set(
      "nonce",
      nonce
    );
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location:
        authorizationUrl.toString(),

      "Set-Cookie":
        setCookie(
          "__Host-oauth-tx",
          oauthCookie,
          600,
          "Lax"
        ),

      "Cache-Control":
        "no-store",
    },
  });
}
