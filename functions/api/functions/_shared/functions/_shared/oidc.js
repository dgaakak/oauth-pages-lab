function decodeBase64Url(value) {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");

  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));

  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function validateGoogleIdToken(idToken, expectedClientId, expectedNonce) {
  const parts = idToken.split(".");

  if (parts.length !== 3) {
    throw new Error("invalid_id_token");
  }

  const header = decodeBase64Url(parts[0]);
  const payload = decodeBase64Url(parts[1]);

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("invalid_id_token");
  }

  const discoveryResponse = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );

  if (!discoveryResponse.ok) {
    throw new Error("oidc_discovery_failed");
  }

  const discovery = await discoveryResponse.json();

  if (discovery.issuer !== "https://accounts.google.com") {
    throw new Error("invalid_issuer");
  }

  const jwksResponse = await fetch(discovery.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error("jwks_failed");
  }

  const jwks = await jwksResponse.json();
  const jwk = jwks.keys.find(key => key.kid === header.kid);

  if (!jwk) {
    throw new Error("unknown_key");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );

  const signingInput = new TextEncoder().encode(
    `${parts[0]}.${parts[1]}`
  );

  const signature = Uint8Array.from(
    atob(
      parts[2]
        .replace(/-/g, "+")
        .replace(/_/g, "/")
        .padEnd(Math.ceil(parts[2].length / 4) * 4, "=")
    ),
    c => c.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signingInput
  );

  if (!valid) {
    throw new Error("invalid_signature");
  }

  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== "https://accounts.google.com") {
    throw new Error("invalid_issuer");
  }

  if (payload.aud !== expectedClientId) {
    throw new Error("invalid_audience");
  }

  if (!payload.exp || payload.exp <= now) {
    throw new Error("expired_token");
  }

  if (!payload.iat || payload.iat > now + 300) {
    throw new Error("invalid_iat");
  }

  if (payload.nonce !== expectedNonce) {
    throw new Error("invalid_nonce");
  }

  if (!payload.sub) {
    throw new Error("missing_subject");
  }

  return {
    subject: String(payload.sub),
    name: payload.name || null,
    email: payload.email || null,
  };
}
