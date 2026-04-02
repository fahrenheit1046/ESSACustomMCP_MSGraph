import express from "express";
import session from "express-session";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { Pool } from "pg";
import fetch from "node-fetch";
import { z } from "zod";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const TENANT_ID = process.env.AZURE_TENANT_ID;
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || "changeme";
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const SCOPES = ["Mail.ReadWrite", "offline_access"];
const ADMIN_EMAIL = "mm@essallp.com";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_tokens (
      user_id TEXT PRIMARY KEY,
      user_email TEXT,
      token_cache TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Add user_email column if it doesn't exist (for existing deployments)
  await pool.query(`
    ALTER TABLE user_tokens ADD COLUMN IF NOT EXISTS user_email TEXT
  `);
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

// Get delegated access token for a specific user
async function getTokenForUser(userId) {
  const msalApp = createMsalApp();
  const row = await pool.query("SELECT token_cache FROM user_tokens WHERE user_id = $1", [userId]);
  if (row.rows.length === 0) throw new Error("User not authenticated");

  const cache = msalApp.getTokenCache();
  cache.deserialize(row.rows[0].token_cache);

  const accounts = await cache.getAllAccounts();
  if (!accounts || accounts.length === 0) throw new Error("No accounts in cache");

  const result = await msalApp.acquireTokenSilent({
    scopes: SCOPES,
    account: accounts[0],
  });

  const serialized = cache.serialize();
  await pool.query(
    "UPDATE user_tokens SET token_cache = $1, updated_at = NOW() WHERE user_id = $2",
    [serialized, userId]
  );

  return result.accessToken;
}

// Get application-level token for admin operations
async function getAppToken() {
  const msalApp = createMsalApp();
  const result = await msalApp.acquireTokenByClientCredentials({
    scopes: ["https://graph.microsoft.com/.default"],
  });
  return result.accessToken;
}

// Get the email address for a user ID
async function getUserEmail(userId) {
  const row = await pool.query("SELECT user_email FROM user_tokens WHERE user_id = $1", [userId]);
  return row.rows[0]?.user_email || null;
}

// Graph API call using delegated token (acts as the signed-in user)
async function graph(method, path, body, userId) {
  const token = await getTokenForUser(userId);
  return graphWithToken(method, path, body, token);
}

// Graph API call using an explicit token (used for app-level admin calls)
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
  if (data.value && data.value.length > 0) {
    return new Date(data.value[0].receivedDateTime);
  }
  return null;
}

function createMcpServer(userId, userEmail) {
  const server = new McpServer({
    name: "outlook-mail-tools",
    version: "3.0.0",
  });

  const isAdmin = userEmail && userEmail.toLowerCase() === ADMIN_EMAIL.toLowerCase();

  // ─── FOLDER TOOLS ────────────────────────────────────────────────────────

  server.tool("list_project_folders", "List all Project folders under Inbox/Deals", {}, async () => {
    try {
      const inbox = await graph("GET", "/me/mailFolders/Inbox/childFolders?$top=100", null, userId);
      const deals = inbox.value?.find((f) => f.displayName === "Deals");
      if (!deals) return { content: [{ type: "text", text: "Deals folder not found" }] };

      const folders = await getAllFolders(`/${deals.id}`, userId);
      const projects = folders.filter(
        (f) =>
          f.displayName.startsWith("Project ") &&
          !f.displayName.endsWith("- archive") &&
          !f.displayName.endsWith("- Archive")
      );

      const lines = projects.map((f) => `${f.displayName} (id: ${f.id})`);
      return { content: [{ type: "text", text: lines.join("\n") }] };
    } catch (e) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }] };
    }
  });

  server.tool(
    "rename_mail_folder",
    "Rename a mail folder by ID",
    { folderId: z.string(), newName: z.string() },
    async ({ folderId, newName }) => {
      try {
        await graph("PATCH", `/me/mailFolders/${folderId}`, { displayName: newName }, userId);
        return { content: [{ type: "text", text: `Renamed to: ${newName}` }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  server.tool(
    "move_mail_folder",
    "Move a mail folder to a new parent folder",
    { folderId: z.string(), destinationId: z.string() },
    async ({ folderId, destinationId }) => {
      try {
        await graph("POST", `/me/mailFolders/${folderId}/move`, { destinationId }, userId);
        return { content: [{ type: "text", text: "Folder moved successfully" }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  server.tool(
    "run_archive_and_move",
    "Archive inactive Project folders (no email in 6 weeks) by renaming and moving to zArchive",
    {},
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
          zArchive = await graph(
            "POST",
            `/me/mailFolders/${deals.id}/childFolders`,
            { displayName: "zArchive" },
            userId
          );
        }

        const projects = folders.filter(
          (f) =>
            f.displayName.startsWith("Project ") &&
            !f.displayName.endsWith("- archive") &&
            !f.displayName.endsWith("- Archive") &&
            f.id !== zArchive.id
        );

        const results = [];
        for (const folder of projects) {
          const latest = await getLatestMessageDate(folder.id, userId);
          const inactive = !latest || latest < cutoff;

          if (inactive) {
            const newName = `${folder.displayName} - Archive`;
            await graph("PATCH", `/me/mailFolders/${folder.id}`, { displayName: newName }, userId);
            await graph(
              "POST",
              `/me/mailFolders/${folder.id}/move`,
              { destinationId: zArchive.id },
              userId
            );
            const lastStr = latest ? latest.toISOString().split("T")[0] : "never";
            results.push(`ARCHIVED: ${folder.displayName} (last email: ${lastStr})`);
          } else {
            results.push(`ACTIVE: ${folder.displayName}`);
          }
        }

        return {
          content: [{ type: "text", text: results.length ? results.join("\n") : "No project folders found" }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  // ─── EMAIL TOOLS ─────────────────────────────────────────────────────────

  server.tool(
    "send_email",
    "Send an email from your account",
    {
      to: z.string().describe("Recipient email address"),
      subject: z.string().describe("Email subject"),
      body: z.string().describe("Email body (plain text)"),
      cc: z.string().optional().describe("CC email address (optional)"),
    },
    async ({ to, subject, body, cc }) => {
      try {
        const message = {
          subject,
          body: { contentType: "Text", content: body },
          toRecipients: [{ emailAddress: { address: to } }],
        };
        if (cc) {
          message.ccRecipients = [{ emailAddress: { address: cc } }];
        }
        await graph("POST", "/me/sendMail", { message, saveToSentItems: true }, userId);
        return { content: [{ type: "text", text: `Email sent to ${to}` }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  server.tool(
    "archive_email",
    "Move an email to the Archive folder",
    { messageId: z.string().describe("The message ID to archive") },
    async ({ messageId }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/move`, { destinationId: "archive" }, userId);
        return { content: [{ type: "text", text: "Email archived successfully" }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  server.tool(
    "search_emails",
    "Search emails in your mailbox",
    {
      query: z.string().describe("Search query (e.g. 'from:john@example.com' or keyword)"),
      folder: z.string().optional().describe("Folder to search: inbox, sentitems, drafts, archive (default: inbox)"),
      top: z.string().optional().describe("Number of results to return (default: 10, max: 50)"),
    },
    async ({ query, folder, top }) => {
      try {
        const folderName = folder || "inbox";
        const limit = Math.min(parseInt(top || "10", 10), 50);
        const data = await graph(
          "GET",
          `/me/mailFolders/${folderName}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview`,
          null,
          userId
        );
        if (!data.value || data.value.length === 0) {
          return { content: [{ type: "text", text: "No emails found" }] };
        }
        const lines = data.value.map((m) =>
          `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`
        );
        return { content: [{ type: "text", text: lines.join("\n---\n") }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  server.tool(
    "read_email",
    "Read the full content of an email by message ID",
    { messageId: z.string().describe("The message ID to read") },
    async ({ messageId }) => {
      try {
        const m = await graph(
          "GET",
          `/me/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body`,
          null,
          userId
        );
        const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
        const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
        const text = [
          `Subject: ${m.subject}`,
          `From: ${m.from?.emailAddress?.address}`,
          `To: ${to}`,
          cc ? `CC: ${cc}` : null,
          `Date: ${m.receivedDateTime}`,
          ``,
          m.body?.content?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
        ]
          .filter(Boolean)
          .join("\n");
        return { content: [{ type: "text", text }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Error: ${e.message}` }] };
      }
    }
  );

  // ─── ADMIN TOOLS (mm@essallp.com only) ───────────────────────────────────

  if (isAdmin) {
    server.tool(
      "admin_search_emails",
      "ADMIN: Search emails in any ESSA user's mailbox (read-only)",
      {
        userEmail: z.string().describe("The ESSA user's email address to search"),
        query: z.string().describe("Search query"),
        top: z.string().optional().describe("Number of results (default: 10, max: 50)"),
      },
      async ({ userEmail, query, top }) => {
        try {
          const token = await getAppToken();
          const limit = Math.min(parseInt(top || "10", 10), 50);
          const data = await graphWithToken(
            "GET",
            `/users/${encodeURIComponent(userEmail)}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview`,
            null,
            token
          );
          if (!data.value || data.value.length === 0) {
            return { content: [{ type: "text", text: `No emails found for ${userEmail}` }] };
          }
          const lines = data.value.map((m) =>
            `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`
          );
          return { content: [{ type: "text", text: `Results for ${userEmail}:\n\n` + lines.join("\n---\n") }] };
        } catch (e) {
          return { content: [{ type: "text", text: `Error: ${e.message}` }] };
        }
      }
    );

    server.tool(
      "admin_read_email",
      "ADMIN: Read a specific email from any ESSA user's mailbox (read-only)",
      {
        userEmail: z.string().describe("The ESSA user's email address"),
        messageId: z.string().describe("The message ID to read"),
      },
      async ({ userEmail, messageId }) => {
        try {
          const token = await getAppToken();
          const m = await graphWithToken(
            "GET",
            `/users/${encodeURIComponent(userEmail)}/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body`,
            null,
            token
          );
          const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
          const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
          const text = [
            `[Reading on behalf of ${userEmail}]`,
            `Subject: ${m.subject}`,
            `From: ${m.from?.emailAddress?.address}`,
            `To: ${to}`,
            cc ? `CC: ${cc}` : null,
            `Date: ${m.receivedDateTime}`,
            ``,
            m.body?.content?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
          ]
            .filter(Boolean)
            .join("\n");
          return { content: [{ type: "text", text }] };
        } catch (e) {
          return { content: [{ type: "text", text: `Error: ${e.message}` }] };
        }
      }
    );
  }

  return server;
}

// ─── EXPRESS APP ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "mcp-outlook", version: "3.0.0" });
});

app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: SCOPES.join(" "),
    state,
    response_mode: "query",
  });

  res.redirect(
    `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`
  );
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send(`Auth error: ${error}`);
    if (state !== req.session.oauthState) return res.status(400).send("Invalid state");

    const msalApp = createMsalApp();
    const result = await msalApp.acquireTokenByCode({
      code,
      scopes: SCOPES,
      redirectUri: REDIRECT_URI,
    });

    const userId = result.account.homeAccountId;
    const userEmail = result.account.username;
    const cacheData = msalApp.getTokenCache().serialize();

    await pool.query(
      `INSERT INTO user_tokens (user_id, user_email, token_cache) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET user_email = $2, token_cache = $3, updated_at = NOW()`,
      [userId, userEmail, cacheData]
    );

    req.session.userId = userId;
    res.send(`
      <h2>Authenticated successfully!</h2>
      <p>Signed in as: <code>${userEmail}</code></p>
      <p>Your MCP endpoint: <code>${BASE_URL}/mcp/${userId}</code></p>
      <p>Add this URL to your Claude MCP config.</p>
    `);
  } catch (e) {
    res.status(500).send(`Callback error: ${e.message}`);
  }
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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MCP Outlook server v3 listening on 0.0.0.0:${PORT}`);
  console.log(`Auth: ${BASE_URL}/auth/login`);
  console.log(`DATABASE_URL set: ${!!process.env.DATABASE_URL}`);
  console.log(`CLIENT_ID set: ${!!CLIENT_ID}`);
  console.log(`TENANT_ID set: ${!!TENANT_ID}`);
  console.log(`CLIENT_SECRET set: ${!!CLIENT_SECRET}`);
});

initDb()
  .then(() => console.log("DB initialised successfully"))
  .catch((err) => console.error("DB init failed (non-fatal):", err));
