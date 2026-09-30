export const providers = {
  google: {
    authorizationEndpoint:
      "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint:
      "https://oauth2.googleapis.com/token",
    clientIdEnv: "GOOGLE_CLIENT_ID",
    clientSecretEnv: "GOOGLE_CLIENT_SECRET",
  },

  github: {
    authorizationEndpoint:
      "https://github.com/login/oauth/authorize",
    tokenEndpoint:
      "https://github.com/login/oauth/access_token",
    clientIdEnv: "GITHUB_CLIENT_ID",
    clientSecretEnv: "GITHUB_CLIENT_SECRET",
  },
};

export function getProvider(name) {
  if (name !== "google" && name !== "github") {
    return null;
  }

  return providers[name];
}
