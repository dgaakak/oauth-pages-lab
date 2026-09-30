function base64url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function randomBase64url() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export async function sha256Base64url(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return base64url(new Uint8Array(digest));
}
