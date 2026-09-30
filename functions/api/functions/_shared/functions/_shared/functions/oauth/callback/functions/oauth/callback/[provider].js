import { randomBase64url, sha256Base64url } from "../../_shared/crypto.js";
import { getCookie, setCookie, clearCookie } from "../../_shared/cookies.js";
import { getProvider } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const providerName = context.params.provider;
  const provider = getProvider(providerName);

  if (!provider) {
    return new Response("Not Found", { status: 404 });
  }

  const env = context.env;
  const baseUrl = env.PUBLIC_BASE_URL;

  if (!baseUrl) {
    return new Response("Configuration error", { status: 500 });
  }

  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error || !code || !state) {
    return new Response("OAuth error", { status: 400 });
  }

  const oauthCookie = getCookie(
    context.request,
    "__Host-oauth-tx"
  );

  if (!oauthCookie) {
    return new Response("Invalid OAuth transaction", {
      status: 400,
    });
  }

  const cookieHash = await sha256Base64url(oauthCookie);
  const stateHash = await sha256Base64url(state);
  const now = Math.floor(Date.now() / 1000);

  const transaction = await env.DB.prepare(
    `SELECT id_hash, provider, state_hash, nonce, code_verifier, expires_at
     FROM oauth_transactions
     WHERE id_hash = ?
       AND expires_at > ?`
  )
    .bind(cookieHash, now)
    .first();

  if (!transaction) {
    return new Response("Invalid OAuth transaction", {
      status: 400,
    });
  }

  if (
    transaction.provider !== providerName ||
    transaction.state_hash !== stateHash
  ) {
    return new Response("Invalid OAuth transaction", {
      status: 400,
    });
  }

  await env.DB.prepare(
    "DELETE FROM oauth_transactions WHERE id_hash = ?"
  )
    .bind(cookieHash)
    .run();

  const redirectUri =
    `${baseUrl}/oauth/callback/${providerName}`;

  let profile;

  if (providerName === "google") {
    const tokenResponse = await fetch(
      provider.tokenEndpoint,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
          code_verifier: transaction.code_verifier,
        }),
      }
    );

    if (!tokenResponse.ok) {
      return new Response("OAuth token exchange failed", {
        status: 400,
      });
    }

    const tokenData = await tokenResponse.json();

    if (!tokenData.id_token) {
      return new Response("Invalid OAuth response", {
        status: 400,
      });
    }

    profile = await validateGoogleIdToken(
      tokenData.id_token,
      env.GOOGLE_CLIENT_ID,
      transaction.nonce
    );
  } else {
    const tokenResponse = await fetch(
      provider.tokenEndpoint,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: new URLSearchParams({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
          code_verifier: transaction.code_verifier,
        }),
      }
    );

    if (!tokenResponse.ok) {
      return new Response("OAuth token exchange failed", {
        status: 400,
      });
    }

    const tokenData = await tokenResponse.json();

    if (
      !tokenData.access_token ||
      String(tokenData.token_type || "").toLowerCase() !==
        "bearer"
    ) {
      return new Response("Invalid OAuth response", {
        status: 400,
      });
    }

    const accessToken = tokenData.access_token;

    const profileResponse = await fetch(
      "https://api.github.com/user",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
        },
      }
    );

    if (!profileResponse.ok) {
      return new Response("GitHub profile request failed", {
        status: 400,
      });
    }

    const githubProfile = await profileResponse.json();

    if (
      !Number.isInteger(githubProfile.id)
    ) {
      return new Response("Invalid GitHub profile", {
        status: 400,
      });
    }

    const revokeResponse = await fetch(
      `https://api.github.com/applications/${encodeURIComponent(
        env.GITHUB_CLIENT_ID
      )}/grant`,
      {
        method: "DELETE",
        headers: {
          Authorization:
            `Basic ${btoa(
              `${env.GITHUB_CLIENT_ID}:${env.GITHUB_CLIENT_SECRET}`
            )}`,
          Accept: "application/vnd.github+json",
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2026-03-10",
        },
        body: JSON.stringify({
          access_token: accessToken,
        }),
      }
    );

    if (revokeResponse.status !== 204) {
      return new Response("GitHub token revocation failed", {
        status: 400,
      });
    }

    profile = {
      subject: String(githubProfile.id),
      name: githubProfile.name || githubProfile.login || null,
      email: githubProfile.email || null,
    };
  }

  const sessionValue = randomBase64url();
  const sessionHash = await sha256Base64url(sessionValue);
  const sessionExpiresAt = now + 28800;

  await env.DB.prepare(
    `INSERT INTO sessions
      (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      sessionHash,
      providerName === "google"
        ? "https://accounts.google.com"
        : "https://github.com",
      profile.subject,
      profile.email,
      profile.name,
      sessionExpiresAt,
      now
    )
    .run();

  const headers = new Headers({
    Location: baseUrl,
    "Cache-Control": "no-store",
  });

  headers.append(
    "Set-Cookie",
    setCookie(
      "__Host-session",
      sessionValue,
      28800,
      "Strict"
    )
  );

  headers.append(
    "Set-Cookie",
    clearCookie(
      "__Host-oauth-tx",
      "Lax"
    )
  );

  return new Response(null, {
    status: 302,
    headers,
  });
}
