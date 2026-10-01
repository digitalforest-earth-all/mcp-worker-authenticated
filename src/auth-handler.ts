import type {
  AuthRequest,
  OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";

interface Env {
  OAUTH_PROVIDER: OAuthHelpers;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  OAUTH_STATE_SECRET: string;
}

const app = new Hono<{ Bindings: Env }>();

const GOOGLE_AUTHORIZE_URL =
  "https://accounts.google.com/o/oauth2/v2/auth";

const GOOGLE_TOKEN_URL =
  "https://oauth2.googleapis.com/token";

const GOOGLE_USERINFO_URL =
  "https://openidconnect.googleapis.com/v1/userinfo";

const CALLBACK_URL =
  "https://mcp-worker-authenticated.digitalforest-earth.workers.dev/callback";

const BUYER_CHECK_URL =
  "https://ai-business-partner-mcp.digitalforest-earth.workers.dev/access-check";

const STATE_MAX_AGE_SECONDS = 10 * 60;

type SignedStatePayload = {
  oauthReqInfo: AuthRequest;
  nonce: string;
  exp: number;
};

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    normalized + "=".repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function getSigningKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"]
  );
}

async function createSignedState(
  payload: SignedStatePayload,
  secret: string
): Promise<string> {
  const encodedPayload = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const key = await getSigningKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(encodedPayload)
  );

  return `${encodedPayload}.${base64UrlEncode(
    new Uint8Array(signature)
  )}`;
}

async function verifySignedState(
  state: string,
  secret: string
): Promise<SignedStatePayload | null> {
  const [encodedPayload, encodedSignature] = state.split(".");

  if (!encodedPayload || !encodedSignature) {
    return null;
  }

  try {
    const key = await getSigningKey(secret);

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlDecode(encodedSignature),
      new TextEncoder().encode(encodedPayload)
    );

    if (!valid) {
      return null;
    }

    const payload = JSON.parse(
      new TextDecoder().decode(
        base64UrlDecode(encodedPayload)
      )
    ) as SignedStatePayload;

    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getCookie(
  cookieHeader: string | undefined,
  name: string
): string | null {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

/**
 * GET /authorize
 *
 * ChatGPT/MCP client starts authorization here.
 * We preserve the MCP OAuth request inside a signed state,
 * then redirect the user to Google for identity verification.
 */
app.get("/authorize", async (c) => {
  const oauthReqInfo: AuthRequest =
    await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);

  const clientInfo =
    await c.env.OAUTH_PROVIDER.lookupClient(
      oauthReqInfo.clientId
    );

  if (!clientInfo) {
    return c.text("Invalid client_id", 400);
  }

  if (
    !c.env.GOOGLE_CLIENT_ID ||
    !c.env.GOOGLE_CLIENT_SECRET ||
    !c.env.OAUTH_STATE_SECRET
  ) {
    return c.text(
      "OAuth server configuration is incomplete",
      500
    );
  }

  const nonce = crypto.randomUUID();

  const state = await createSignedState(
    {
      oauthReqInfo,
      nonce,
      exp: Date.now() + STATE_MAX_AGE_SECONDS * 1000,
    },
    c.env.OAUTH_STATE_SECRET
  );

  const googleUrl = new URL(GOOGLE_AUTHORIZE_URL);

  googleUrl.searchParams.set(
    "client_id",
    c.env.GOOGLE_CLIENT_ID
  );

  googleUrl.searchParams.set(
    "redirect_uri",
    CALLBACK_URL
  );

  googleUrl.searchParams.set(
    "response_type",
    "code"
  );

  googleUrl.searchParams.set(
    "scope",
    "openid email profile"
  );

  googleUrl.searchParams.set(
    "state",
    state
  );

  googleUrl.searchParams.set(
    "prompt",
    "select_account"
  );

  const response = c.redirect(googleUrl.toString(), 302);

  response.headers.append(
    "Set-Cookie",
    [
      `mcp_oauth_nonce=${encodeURIComponent(nonce)}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      `Max-Age=${STATE_MAX_AGE_SECONDS}`,
      "Path=/",
    ].join("; ")
  );

  return response;
});

/**
 * GET /callback
 *
 * Google redirects the authenticated user here.
 * We:
 * 1. Validate signed state + browser nonce
 * 2. Exchange Google code for tokens
 * 3. Fetch verified Google identity
 * 4. Check the email against the buyer list
 * 5. Only then complete MCP OAuth authorization
 */
app.get("/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const googleError = c.req.query("error");

  if (googleError) {
    return c.text(
      `Google authorization failed: ${googleError}`,
      400
    );
  }

  if (!code || !state) {
    return c.text(
      "Missing authorization code or state",
      400
    );
  }

  const statePayload = await verifySignedState(
    state,
    c.env.OAUTH_STATE_SECRET
  );

  if (!statePayload) {
    return c.text(
      "Invalid or expired OAuth state",
      400
    );
  }

  const cookieNonce = getCookie(
    c.req.header("Cookie"),
    "mcp_oauth_nonce"
  );

  if (
    !cookieNonce ||
    cookieNonce !== statePayload.nonce
  ) {
    return c.text(
      "OAuth session validation failed",
      400
    );
  }

  const tokenResponse = await fetch(
    GOOGLE_TOKEN_URL,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret:
          c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: CALLBACK_URL,
        grant_type: "authorization_code",
      }),
    }
  );

  if (!tokenResponse.ok) {
    const errorText = await tokenResponse.text();

    console.error(
      "Google token exchange failed:",
      errorText
    );

    return c.text(
      "Google authentication failed",
      401
    );
  }

  const tokenData = (await tokenResponse.json()) as {
    access_token?: string;
  };

  if (!tokenData.access_token) {
    return c.text(
      "Google access token missing",
      401
    );
  }

  const userInfoResponse = await fetch(
    GOOGLE_USERINFO_URL,
    {
      headers: {
        Authorization:
          `Bearer ${tokenData.access_token}`,
      },
    }
  );

  if (!userInfoResponse.ok) {
    return c.text(
      "Unable to retrieve Google user profile",
      401
    );
  }

  const googleUser = (await userInfoResponse.json()) as {
    sub?: string;
    email?: string;
    email_verified?: boolean;
    name?: string;
  };

  const email =
    googleUser.email?.trim().toLowerCase();

  if (
    !googleUser.sub ||
    !email ||
    googleUser.email_verified !== true
  ) {
    return c.text(
      "A verified Google email address is required",
      403
    );
  }

  /**
   * Buyer authorization
   */
  const buyerCheckResponse = await fetch(
    BUYER_CHECK_URL,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email }),
    }
  );

  if (!buyerCheckResponse.ok) {
    return c.text(
      "Unable to verify purchase status",
      503
    );
  }

  const buyerCheck =
    (await buyerCheckResponse.json()) as {
      authorized?: boolean;
      reason?: string;
    };

  if (buyerCheck.authorized !== true) {
    return c.html(
      `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
          >
          <title>Access unavailable</title>
        </head>
        <body
          style="
            font-family:
              -apple-system,
              BlinkMacSystemFont,
              'Segoe UI',
              sans-serif;
            max-width:600px;
            margin:60px auto;
            padding:24px;
            line-height:1.7;
          "
        >
          <h1>利用権限を確認できませんでした</h1>
          <p>
            このGoogleアカウントは、
            AI事業パートナーの購入者として
            登録されていません。
          </p>
          <p>
            購入時に登録したGoogleメールアドレスで
            ログインしてください。
          </p>
        </body>
      </html>
      `,
      403
    );
  }

  const oauthReqInfo =
    statePayload.oauthReqInfo;

  const clientInfo =
    await c.env.OAUTH_PROVIDER.lookupClient(
      oauthReqInfo.clientId
    );

  if (!clientInfo) {
    return c.text(
      "Invalid MCP client",
      400
    );
  }

  const userProfile = {
    userId: googleUser.sub,
    username:
      googleUser.name || email,
    email,
  };

  const { redirectTo } =
    await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: oauthReqInfo,
      userId: googleUser.sub,
      metadata: {
        label:
          "AI Business Partner Access",
        clientName:
          clientInfo.clientName ||
          "Unknown Client",
      },
      scope: oauthReqInfo.scope,
      props: userProfile,
    });
console.log("OAuth redirectTo:", redirectTo);
  const response = c.redirect(
    redirectTo,
    302
  );

  response.headers.append(
    "Set-Cookie",
    [
      "mcp_oauth_nonce=",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Max-Age=0",
      "Path=/",
    ].join("; ")
  );

  return response;
});

/**
 * GET /
 *
 * Basic server information.
 */
app.get("/", (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta
          name="viewport"
          content="width=device-width, initial-scale=1.0"
        >
        <title>AI Business Partner MCP</title>
      </head>
      <body
        style="
          font-family:
            -apple-system,
            BlinkMacSystemFont,
            'Segoe UI',
            sans-serif;
          max-width:800px;
          margin:50px auto;
          padding:20px;
          line-height:1.6;
        "
      >
        <h1>AI Business Partner MCP</h1>
        <p>
          Authenticated MCP server for
          AI Business Partner.
        </p>

        <h2>Authentication</h2>
        <p>
          Google identity verification
          and purchaser authorization are required.
        </p>

        <h2>Available Endpoints</h2>
        <ul>
          <li>/mcp</li>
          <li>/authorize</li>
          <li>/callback</li>
        </ul>
      </body>
    </html>
  `);
});

export { app as AuthHandler };
