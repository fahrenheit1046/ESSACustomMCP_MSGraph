import express from "express";
import session from "express-session";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { Pool } from "pg";
import fetch from "node-fetch";
import { z } from "zod";
import { randomBytes, createHash } from "crypto";

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const TENANT_ID = process.env.AZURE_TENANT_ID;
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || "changeme";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const MS_REDIRECT_URI = `${BASE_URL}/oauth/ms-callback`;
const LEGACY_REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = ["Mail.ReadWrite", "offline_access"];
const ADMIN_EMAIL = "mm@essallp.com";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_tokens (
      user_id    TEXT PRIMARY KEY,
      user_email TEXT,
      token_cache TEXT NOT NULL,
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`ALTER TABLE user_tokens ADD COLUMN IF NOT EXISTS user_email TEXT`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pending_auth (
      state          TEXT PRIMARY KEY,
      redirect_uri   TEXT NOT NULL,
      code_challenge TEXT,
      our_auth_code  TEXT,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS mcp_sessions (
      access_token TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL,
      created_at   TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`DELETE FROM pending_auth WHERE created_at < NOW() - INTERVAL '10 minutes'`);
}

function createMsalApp() {
  return new ConfidentialClientApplication({
    auth: {
      clientId: CLIENT_ID,
      authority: `https://login.microsoftonline.com/${TENANT_ID}`,
      clientSecret: CLIENT_SECRET,
    },
  });
}

async function getTokenForUser(userId) {
  const msalApp = createMsalApp();
  const row = await pool.query("SELECT token_cache FROM user_tokens WHERE user_id = $1", [userId]);
  if (row.rows.length === 0) throw new Error("User not authenticated");
  const cache = msalApp.getTokenCache();
  cache.deserialize(row.rows[0].token_cache);
  const accounts = await cache.getAllAccounts();
  if (!accounts || accounts.length === 0) throw new Error("No accounts in cache");
  const result = await msalApp.acquireTokenSilent({ scopes: SCOPES, account: accounts[0] });
  const serialized = cache.serialize();
  await pool.query(
    "UPDATE user_tokens SET token_cache = $1, updated_at = NOW() WHERE user_id = $2",
    [serialized, userId]
  );
  return result.accessToken;
}

async function getAppToken() {
  const msalApp = createMsalApp();
  const result = await msalApp.acquireTokenByClientCredential({
    scopes: ["https://graph.microsoft.com/.default"],
  });
  return result.accessToken;
}

async function getUserEmail(userId) {
  const row = await pool.query("SELECT user_email FROM user_tokens WHERE user_id = $1", [userId]);
  return row.rows[0]?.user_email || null;
}

async function graph(method, path, body, userId) {
  const token = await getTokenForUser(userId);
  return graphWithToken(method, path, body, token);
}

async function graphWithToken(method, path, body, token) {
  const res = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Graph ${method} ${path} => ${res.status}: ${err}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function getAllFolders(parentPath, userId) {
  const data = await graph("GET", `/me/mailFolders${parentPath}/childFolders?$top=100`, null, userId);
  return data.value || [];
}

async function getLatestMessageDate(folderId, userId) {
  const data = await graph(
    "GET",
    `/me/mailFolders/${folderId}/messages?$top=1&$select=receivedDateTime&$orderby=receivedDateTime desc`,
    null,
    userId
  );
  if (data.value && data.value.length > 0) return new Date(data.value[0].receivedDateTime);
  return null;
}

function verifyPKCE(codeVerifier, codeChallenge) {
  if (!codeChallenge || !codeVerifier) return true;
  const hash = createHash("sha256").update(codeVerifier).digest("base64url");
  return hash === codeChallenge;
}

function createMcpServer(userId, userEmail) {
  const server = new McpServer({ name: "essa-outlook", version: "3.3.0" });
  const isAdmin = userEmail && userEmail.toLowerCase() === ADMIN_EMAIL.toLowerCase();

  if (isAdmin) {
  server.tool("list_project_folders", "List all Project folders under Inbox/Deals", {}, async () => {
    try {
      const inbox = await graph("GET", "/me/mailFolders/Inbox/childFolders?$top=100", null, userId);
      const deals = inbox.value?.find((f) => f.displayName === "Deals");
      if (!deals) return { content: [{ type: "text", text: "Deals folder not found" }] };
      const folders = await getAllFolders(`/${deals.id}`, userId);
      const projects = folders.filter(
        (f) => f.displayName.startsWith("Project ") &&
          !f.displayName.endsWith("- archive") && !f.displayName.endsWith("- Archive")
      );
      const lines = projects.map((f) => `${f.displayName} (id: ${f.id})`);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
  });
  server.tool("rename_mail_folder", "Rename a mail folder by ID",
    { folderId: z.string(), newName: z.string() },
    async ({ folderId, newName }) => {
      try {
        await graph("PATCH", `/me/mailFolders/${folderId}`, { displayName: newName }, userId);
        return { content: [{ type: "text", text: `Renamed to: ${newName}` }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  server.tool("move_mail_folder", "Move a mail folder to a new parent folder",
    { folderId: z.string(), destinationId: z.string() },
    async ({ folderId, destinationId }) => {
      try {
        await graph("POST", `/me/mailFolders/${folderId}/move`, { destinationId }, userId);
        return { content: [{ type: "text", text: "Folder moved successfully" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  server.tool("run_archive_and_move",
    "Archive inactive Project folders (no email in 6 weeks) by renaming and moving to zArchive", {},
    async () => {
      try {
        const SIX_WEEKS_MS = 6 * 7 * 24 * 60 * 60 * 1000;
        const cutoff = new Date(Date.now() - SIX_WEEKS_MS);
        const inbox = await graph("GET", "/me/mailFolders/Inbox/childFolders?$top=100", null, userId);
        const deals = inbox.value?.find((f) => f.displayName === "Deals");
        if (!deals) return { content: [{ type: "text", text: "Deals folder not found" }] };
        const folders = await getAllFolders(`/${deals.id}`, userId);
        let zArchive = folders.find((f) => f.displayName === "zArchive");
        if (!zArchive) {
          zArchive = await graph("POST", `/me/mailFolders/${deals.id}/childFolders`, { displayName: "zArchive" }, userId);
        }
        const projects = folders.filter((f) =>
          f.displayName.startsWith("Project ") &&
          !f.displayName.endsWith("- archive") && !f.displayName.endsWith("- Archive") &&
          f.id !== zArchive.id
        );
        const results = [];
        for (const folder of projects) {
          const latest = await getLatestMessageDate(folder.id, userId);
          const inactive = !latest || latest < cutoff;
          if (inactive) {
            const newName = `${folder.displayName} - Archive`;
            await graph("PATCH", `/me/mailFolders/${folder.id}`, { displayName: newName }, userId);
            await graph("POST", `/me/mailFolders/${folder.id}/move`, { destinationId: zArchive.id }, userId);
            const lastStr = latest ? latest.toISOString().split("T")[0] : "never";
            results.push(`ARCHIVED: ${folder.displayName} (last email: ${lastStr})`);
          } else {
            results.push(`ACTIVE: ${folder.displayName}`);
          }
        }
        return { content: [{ type: "text", text: results.length ? results.join("\n") : "No project folders found" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  } // end admin folder tools

  server.tool("send_email", "Send an email from your account",
    { to: z.string().describe("Recipient email address"), subject: z.string().describe("Email subject"), body: z.string().describe("Email body (plain text)"), cc: z.string().optional().describe("CC email address (optional)") },
    async ({ to, subject, body, cc }) => {
      try {
        const message = { subject, body: { contentType: "Text", content: body }, toRecipients: [{ emailAddress: { address: to } }] };
        if (cc) message.ccRecipients = [{ emailAddress: { address: cc } }];
        await graph("POST", "/me/sendMail", { message, saveToSentItems: true }, userId);
        return { content: [{ type: "text", text: `Email sent to ${to}` }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  server.tool("archive_email", "Move an email to the Archive folder",
    { messageId: z.string().describe("The message ID to archive") },
    async ({ messageId }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/move`, { destinationId: "archive" }, userId);
        return { content: [{ type: "text", text: "Email archived successfully" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  server.tool("search_emails", "Search emails in your mailbox",
    { query: z.string().describe("Search query (e.g. 'from:john@example.com' or keyword)"), folder: z.string().optional().describe("Folder: inbox, sentitems, drafts, archive (default: inbox)"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
    async ({ query, folder, top }) => {
      try {
        const folderName = folder || "inbox";
        const limit = Math.min(parseInt(top || "10", 10), 50);
        const data = await graph("GET", `/me/mailFolders/${folderName}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview`, null, userId);
        if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: "No emails found" }] };
        const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
        return { content: [{ type: "text", text: lines.join("\n---\n") }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );
  server.tool("read_email", "Read the full content of an email by message ID",
    { messageId: z.string().describe("The message ID to read") },
    async ({ messageId }) => {
      try {
        const m = await graph("GET", `/me/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body`, null, userId);
        const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
        const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
        const text = [`Subject: ${m.subject}`, `From: ${m.from?.emailAddress?.address}`, `To: ${to}`, cc ? `CC: ${cc}` : null, `Date: ${m.receivedDateTime}`, ``, m.body?.content?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()].filter(Boolean).join("\n");
        return { content: [{ type: "text", text }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  if (isAdmin) {
    server.tool("admin_search_emails", "ADMIN: Search emails in any ESSA user's mailbox (read-only)",
      { userEmail: z.string().describe("The ESSA user's email address to search"), query: z.string().describe("Search query"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
      async ({ userEmail, query, top }) => {
        try {
          const token = await getAppToken();
          const limit = Math.min(parseInt(top || "10", 10), 50);
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(userEmail)}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview`, null, token);
          if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: `No emails found for ${userEmail}` }] };
          const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
          return { content: [{ type: "text", text: `Results for ${userEmail}:\n\n` + lines.join("\n---\n") }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );
    server.tool("admin_read_email", "ADMIN: Read a specific email from any ESSA user's mailbox (read-only)",
      { userEmail: z.string().describe("The ESSA user's email address"), messageId: z.string().describe("The message ID to read") },
      async ({ userEmail, messageId }) => {
        try {
          const token = await getAppToken();
          const m = await graphWithToken("GET", `/users/${encodeURIComponent(userEmail)}/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body`, null, token);
          const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
          const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
          const text = [`[Reading on behalf of ${userEmail}]`, `Subject: ${m.subject}`, `From: ${m.from?.emailAddress?.address}`, `To: ${to}`, cc ? `CC: ${cc}` : null, `Date: ${m.receivedDateTime}`, ``, m.body?.content?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()].filter(Boolean).join("\n");
          return { content: [{ type: "text", text }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );
  }
  return server;
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: false } }));

app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
  res.set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version");
  res.set("Access-Control-Expose-Headers", "WWW-Authenticate");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.get("/", (req, res) => res.json({ status: "ok", service: "essa-outlook", version: "3.3.0" }));

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({ resource: `${BASE_URL}/mcp`, authorization_servers: [BASE_URL] });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/oauth/authorize`,
    token_endpoint: `${BASE_URL}/oauth/token`,
    registration_endpoint: `${BASE_URL}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  });
});

app.post("/oauth/register", (req, res) => {
  const clientId = randomBytes(16).toString("hex");
  console.log(`DCR: Registered client "${req.body.client_name || "unknown"}" -> ${clientId}`);
  res.status(201).json({
    client_id: clientId,
    client_name: req.body.client_name || "Claude",
    redirect_uris: req.body.redirect_uris || [],
    grant_types: req.body.grant_types || ["authorization_code"],
    response_types: req.body.response_types || ["code"],
    token_endpoint_auth_method: req.body.token_endpoint_auth_method || "none",
  });
});

app.get("/oauth/authorize", async (req, res) => {
  const { redirect_uri, state, code_challenge, code_challenge_method, client_id } = req.query;
  if (!redirect_uri || !state) return res.status(400).send("Missing redirect_uri or state");
  try {
    await pool.query(
      "INSERT INTO pending_auth (state, redirect_uri, code_challenge) VALUES ($1, $2, $3) ON CONFLICT (state) DO UPDATE SET redirect_uri=$2, code_challenge=$3, created_at=NOW()",
      [state, redirect_uri, code_challenge || null]
    );
  } catch (e) {
    console.error("Failed to save pending_auth:", e);
    return res.status(500).send("Server error during auth init");
  }
  const params = new URLSearchParams({
    client_id: CLIENT_ID, response_type: "code", redirect_uri: MS_REDIRECT_URI,
    scope: SCOPES.join(" "), state, response_mode: "query",
  });
  res.redirect(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`);
});

app.get("/oauth/ms-callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(`Microsoft auth error: ${error}`);
  if (!code || !state) return res.status(400).send("Missing code or state");
  try {
    const pending = await pool.query("SELECT redirect_uri, code_challenge FROM pending_auth WHERE state = $1", [state]);
    if (pending.rows.length === 0) return res.status(400).send("Invalid or expired state");
    const { redirect_uri, code_challenge } = pending.rows[0];
    const msalApp = createMsalApp();
    const result = await msalApp.acquireTokenByCode({ code, scopes: SCOPES, redirectUri: MS_REDIRECT_URI });
    const userId = result.account.homeAccountId;
    const userEmail = result.account.username;
    const cacheData = msalApp.getTokenCache().serialize();
    await pool.query(
      `INSERT INTO user_tokens (user_id, user_email, token_cache) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET user_email=$2, token_cache=$3, updated_at=NOW()`,
      [userId, userEmail, cacheData]
    );
    const ourAuthCode = randomBytes(32).toString("hex");
    await pool.query("UPDATE pending_auth SET our_auth_code = $1 WHERE state = $2", [ourAuthCode, state]);
    const callbackParams = new URLSearchParams({ code: ourAuthCode, state });
    res.redirect(`${redirect_uri}?${callbackParams.toString()}`);
  } catch (e) {
    console.error("OAuth MS callback error:", e);
    res.status(500).send(`Auth failed: ${e.message}`);
  }
});

app.post("/oauth/token", async (req, res) => {
  const { grant_type, code, code_verifier, redirect_uri, client_id } = req.body;
  if (grant_type !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
  if (!code) return res.status(400).json({ error: "missing code" });
  try {
    const pending = await pool.query("SELECT state, code_challenge FROM pending_auth WHERE our_auth_code = $1", [code]);
    if (pending.rows.length === 0) return res.status(400).json({ error: "invalid_grant" });
    const { state, code_challenge } = pending.rows[0];
    if (!verifyPKCE(code_verifier, code_challenge)) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }
    const userRow = await pool.query(
      "SELECT ut.user_id FROM user_tokens ut INNER JOIN pending_auth pa ON pa.state = $1 WHERE ut.updated_at >= pa.created_at ORDER BY ut.updated_at DESC LIMIT 1",
      [state]
    );
    if (userRow.rows.length === 0) return res.status(400).json({ error: "invalid_grant", error_description: "User not found" });
    const userId = userRow.rows[0].user_id;
    const accessToken = randomBytes(48).toString("hex");
    await pool.query("INSERT INTO mcp_sessions (access_token, user_id) VALUES ($1, $2)", [accessToken, userId]);
    await pool.query("DELETE FROM pending_auth WHERE state = $1", [state]);
    res.json({ access_token: accessToken, token_type: "bearer", expires_in: 86400 });
  } catch (e) {
    console.error("Token exchange error:", e);
    res.status(500).json({ error: "server_error", error_description: e.message });
  }
});

app.all("/mcp", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
  const wwwAuth = `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`;
  if (!bearerToken) {
    res.set("WWW-Authenticate", wwwAuth);
    return res.status(401).json({ error: "unauthorized" });
  }
  const sessionRow = await pool.query("SELECT user_id FROM mcp_sessions WHERE access_token = $1", [bearerToken]);
  if (sessionRow.rows.length === 0) {
    res.set("WWW-Authenticate", wwwAuth);
    return res.status(401).json({ error: "invalid_token" });
  }
  const userId = sessionRow.rows[0].user_id;
  const userEmail = await getUserEmail(userId);
  const server = createMcpServer(userId, userEmail);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.all("/mcp/:userId", async (req, res) => {
  const { userId } = req.params;
  const row = await pool.query("SELECT user_id, user_email FROM user_tokens WHERE user_id = $1", [userId]);
  if (row.rows.length === 0) {
    return res.status(401).json({ error: "User not authenticated. Visit /auth/login first." });
  }
  const userEmail = row.rows[0].user_email;
  const server = createMcpServer(userId, userEmail);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get("/auth/login", (req, res) => {
  const state = randomBytes(16).toString("hex");
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: CLIENT_ID, response_type: "code", redirect_uri: LEGACY_REDIRECT_URI,
    scope: SCOPES.join(" "), state, response_mode: "query",
  });
  res.redirect(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send(`Auth error: ${error}`);
    if (state !== req.session.oauthState) return res.status(400).send("Invalid state");
    const msalApp = createMsalApp();
    const result = await msalApp.acquireTokenByCode({ code, scopes: SCOPES, redirectUri: LEGACY_REDIRECT_URI });
    const userId = result.account.homeAccountId;
    const userEmail = result.account.username;
    const cacheData = msalApp.getTokenCache().serialize();
    await pool.query(
      `INSERT INTO user_tokens (user_id, user_email, token_cache) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET user_email=$2, token_cache=$3, updated_at=NOW()`,
      [userId, userEmail, cacheData]
    );
    req.session.userId = userId;
    const mcpUrl = `${BASE_URL}/mcp/${userId}`;
    const configJson = JSON.stringify({ mcpServers: { "essa-outlook": { url: mcpUrl } } }, null, 2);
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ESSA Outlook MCP - Setup Complete</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:740px;margin:40px auto;padding:0 24px;color:#1a1a1a;line-height:1.6}h1{color:#2e7d32}h2{margin-top:2em;border-bottom:1px solid #e0e0e0;padding-bottom:4px}code{background:#f5f5f5;padding:2px 6px;border-radius:3px;font-size:.88em;word-break:break-all}pre{background:#f5f5f5;border:1px solid #ddd;padding:16px;border-radius:6px;overflow-x:auto;font-size:.85em;line-height:1.55}.step{margin:.8em 0 .8em 1.2em}.note{background:#fff8e1;border-left:4px solid #f9a825;padding:12px 16px;border-radius:3px;margin:1.2em 0;font-size:.92em}.footer{margin-top:3em;color:#888;font-size:.82em;border-top:1px solid #eee;padding-top:1em}</style></head>
<body>
<h1>&#x2705; Authenticated Successfully</h1>
<p>Signed in as: <strong>${userEmail}</strong></p>
<h2>Step 1 - Your personal MCP endpoint</h2>
<p>This URL is unique to your account:</p>
<pre>${mcpUrl}</pre>
<h2>Step 2 - Add to Claude Desktop</h2>
<p>Open (or create) the Claude Desktop config file at:</p>
<div class="step"><strong>Windows:</strong> <code>%APPDATA%\\Claude\\claude_desktop_config.json</code></div>
<div class="step"><strong>Mac:</strong> <code>~/Library/Application Support/Claude/claude_desktop_config.json</code></div>
<p>Paste the following into the file:</p>
<pre>${configJson}</pre>
<div class="note"><strong>Tip:</strong> If the file already contains an <code>mcpServers</code> block, just add the <code>"essa-outlook"</code> entry inside it.</div>
<h2>Step 3 - Restart Claude Desktop</h2>
<div class="step">1. Save the config file.</div>
<div class="step">2. Quit Claude Desktop completely and reopen it.</div>
<div class="step">3. Look for the <strong>essa-outlook</strong> tools via the hammer icon in a new chat.</div>
<div class="footer">This endpoint is unique to your Microsoft account. Do not share it.<br>Need to re-authenticate? Visit <a href="/auth/login">/auth/login</a> again.</div>
</body></html>`);
  } catch (e) {
    res.status(500).send(`Callback error: ${e.message}`);
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`ESSA Outlook MCP v3.3 listening on 0.0.0.0:${PORT}`);
  console.log(`Connector URL: ${BASE_URL}/mcp`);
  console.log(`DCR endpoint: ${BASE_URL}/oauth/register`);
  console.log(`DATABASE_URL: ${!!process.env.DATABASE_URL} | CLIENT_ID: ${!!CLIENT_ID} | TENANT_ID: ${!!TENANT_ID} | SECRET: ${!!CLIENT_SECRET}`);
});

initDb()
  .then(() => console.log("DB initialised"))
  .catch((err) => console.error("DB init failed (non-fatal):", err));
