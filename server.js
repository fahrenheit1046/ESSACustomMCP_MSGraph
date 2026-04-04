import express from "express";
import session from "express-session";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ConfidentialClientApplication } from "@azure/msal-node";
import { Pool } from "pg";
import fetch from "node-fetch";
import { z } from "zod";
import { randomBytes, createHash, createCipheriv, createDecipheriv } from "crypto";

// ============================================================
// ESSA Custom MCP - Outlook_eMail  v1.0.0
// Mail-only MCP server with all 16 security fixes from v4.
// Standard tools (18): search_emails, search_folder_emails,
//   read_email, send_email, reply_email, reply_all_email,
//   forward_email, update_email, create_draft, send_draft,
//   list_attachments, download_attachment,
//   list_child_folders, get_folder_by_name, create_folder,
//   rename_folder, move_folder, get_latest_email_in_folder
// Admin tools (18): admin_search_emails, admin_search_folder_emails,
//   admin_read_email, admin_send_email, admin_reply_email,
//   admin_reply_all_email, admin_forward_email, admin_update_email,
//   admin_create_draft, admin_send_draft, admin_list_attachments,
//   admin_download_attachment, admin_list_child_folders,
//   admin_get_folder_by_name, admin_create_folder,
//   admin_rename_folder, admin_move_folder,
//   admin_get_latest_email_in_folder
// Graph scopes: Mail.ReadWrite, Mail.Send, User.Read.All,
//   offline_access
// ============================================================

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const TENANT_ID = process.env.AZURE_TENANT_ID;
const CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const MCP_API_KEY = process.env.MCP_API_KEY;
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;
const MS_REDIRECT_URI = `${BASE_URL}/oauth/ms-callback`;
const LEGACY_REDIRECT_URI = `${BASE_URL}/auth/callback`;
const ADMIN_EMAIL = "mm@essallp.com";
const ALLOWED_REDIRECT_URIS = ["https://claude.ai/api/mcp/auth_callback"];
const VALID_FOLDERS = ["inbox", "sentitems", "drafts", "archive", "junkemail", "deleteditems"];
const SESSION_TTL_HOURS = 24;

// Fix 4: SESSION_SECRET is required — no fallback
if (!SESSION_SECRET) {
  console.error("FATAL: SESSION_SECRET environment variable is required");
  process.exit(1);
}

// Mail-only scopes
const SCOPES = [
  "Mail.ReadWrite", "Mail.Send",
  "User.Read.All",
  "offline_access",
];

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// --- Fix 5: Encryption helpers for token_cache ---
function encrypt(text) {
  if (!TOKEN_ENCRYPTION_KEY) return text;
  const iv = randomBytes(12);
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let enc = cipher.update(text, "utf8", "hex");
  enc += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${tag}:${enc}`;
}

function decrypt(text) {
  if (!TOKEN_ENCRYPTION_KEY) return text;
  if (!text || !text.includes(":")) return text;
  const parts = text.split(":");
  if (parts.length !== 3) return text;
  const key = Buffer.from(TOKEN_ENCRYPTION_KEY, "hex");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(parts[0], "hex"));
  decipher.setAuthTag(Buffer.from(parts[1], "hex"));
  let dec = decipher.update(parts[2], "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

// Fix 15: HTML escape
function escapeHtml(s) {
  if (!s) return "";
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Fix 16: Safe parseInt with fallback
function safeTop(val, def = 10, max = 50) {
  const n = parseInt(val || String(def), 10);
  return isNaN(n) ? def : Math.min(n, max);
}

// --- Database ---
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS user_tokens (
    user_id TEXT PRIMARY KEY, user_email TEXT, token_cache TEXT NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE user_tokens ADD COLUMN IF NOT EXISTS user_email TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS pending_auth (
    state TEXT PRIMARY KEY, redirect_uri TEXT NOT NULL, code_challenge TEXT, our_auth_code TEXT, user_id TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`ALTER TABLE pending_auth ADD COLUMN IF NOT EXISTS user_id TEXT`);
  await pool.query(`CREATE TABLE IF NOT EXISTS mcp_sessions (
    access_token TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS registered_clients (
    client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
  )`);
  await pool.query(`DELETE FROM pending_auth WHERE created_at < NOW() - INTERVAL '10 minutes'`);
  await pool.query(`DELETE FROM mcp_sessions WHERE created_at < NOW() - INTERVAL '${SESSION_TTL_HOURS} hours'`);
  await pool.query(`DELETE FROM registered_clients WHERE created_at < NOW() - INTERVAL '24 hours'`);
}

// --- MSAL ---
function createMsalApp() {
  return new ConfidentialClientApplication({
    auth: { clientId: CLIENT_ID, authority: `https://login.microsoftonline.com/${TENANT_ID}`, clientSecret: CLIENT_SECRET },
  });
}

async function getTokenForUser(userId) {
  const msalApp = createMsalApp();
  const row = await pool.query("SELECT token_cache FROM user_tokens WHERE user_id = $1", [userId]);
  if (row.rows.length === 0) throw new Error("User not authenticated");
  const cache = msalApp.getTokenCache();
  cache.deserialize(decrypt(row.rows[0].token_cache));
  const accounts = await cache.getAllAccounts();
  if (!accounts || accounts.length === 0) throw new Error("No accounts in cache");
  const result = await msalApp.acquireTokenSilent({ scopes: SCOPES, account: accounts[0] });
  await pool.query("UPDATE user_tokens SET token_cache = $1, updated_at = NOW() WHERE user_id = $2", [encrypt(cache.serialize()), userId]);
  return result.accessToken;
}

async function getAppToken() {
  const msalApp = createMsalApp();
  const result = await msalApp.acquireTokenByClientCredential({ scopes: ["https://graph.microsoft.com/.default"] });
  return result.accessToken;
}

async function getUserEmail(userId) {
  const row = await pool.query("SELECT user_email FROM user_tokens WHERE user_id = $1", [userId]);
  return row.rows[0]?.user_email || null;
}

// --- Graph helpers ---
async function graph(method, path, body, userId) {
  const token = await getTokenForUser(userId);
  return graphWithToken(method, path, body, token);
}

async function graphWithToken(method, path, body, token) {
  const res = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Graph ${method} ${path} => ${res.status}: ${err}`);
  }
  if (res.status === 202 || res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  return JSON.parse(text);
}

function verifyPKCE(codeVerifier, codeChallenge) {
  // Fix 8: If code_challenge was provided, code_verifier is required
  if (codeChallenge && !codeVerifier) return false;
  if (!codeChallenge && !codeVerifier) return true;
  const hash = createHash("sha256").update(codeVerifier).digest("base64url");
  return hash === codeChallenge;
}

function stripHtml(html) {
  return (html || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

// ============================================================
// MCP Server Factory
// Fix 10: A new McpServer + transport is created per request.
// ============================================================
function createMcpServer(userId, userEmail) {
  const server = new McpServer({ name: "essa-outlook-email", version: "1.0.0" });
  const isAdmin = userEmail && userEmail.toLowerCase() === ADMIN_EMAIL.toLowerCase();

  // ======== STANDARD MAIL TOOLS (10) ========

  server.tool("search_emails", "Search emails in your mailbox",
    { query: z.string().describe("Search query (KQL syntax supported)"), folder: z.string().optional().describe("Folder: inbox, sentitems, drafts, archive, junkemail, deleteditems (default: inbox)"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
    async ({ query, folder, top }) => {
      try {
        // Fix 11: Validate folder
        const f = VALID_FOLDERS.includes(folder) ? folder : "inbox";
        const limit = safeTop(top);
        const data = await graph("GET", `/me/mailFolders/${f}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview,isRead`, null, userId);
        if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: "No emails found" }] };
        const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nRead: ${m.isRead}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
        return { content: [{ type: "text", text: lines.join("\n---\n") }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("search_folder_emails", "Search emails in a specific mail folder by folder ID",
    { folderId: z.string().describe("Mail folder ID (use well-known names like inbox, sentitems, or a Graph folder ID)"), query: z.string().optional().describe("Search query (omit to list recent)"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
    async ({ folderId, query, top }) => {
      try {
        const limit = safeTop(top);
        const searchParam = query ? `$search="${encodeURIComponent(query)}"&` : "";
        const data = await graph("GET", `/me/mailFolders/${folderId}/messages?${searchParam}$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview,isRead&$orderby=receivedDateTime desc`, null, userId);
        if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: "No emails found in this folder" }] };
        const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nRead: ${m.isRead}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
        return { content: [{ type: "text", text: lines.join("\n---\n") }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("read_email", "Read the full content of an email by message ID",
    { messageId: z.string().describe("The message ID to read") },
    async ({ messageId }) => {
      try {
        const m = await graph("GET", `/me/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,flag,importance`, null, userId);
        const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
        const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
        const text = [`Subject: ${m.subject}`, `From: ${m.from?.emailAddress?.address}`, `To: ${to}`, cc ? `CC: ${cc}` : null, `Date: ${m.receivedDateTime}`, `Read: ${m.isRead}`, `Flag: ${m.flag?.flagStatus || "none"}`, `Importance: ${m.importance || "normal"}`, ``, stripHtml(m.body?.content)].filter(Boolean).join("\n");
        return { content: [{ type: "text", text }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("send_email", "Send an email from your account",
    { to: z.string().describe("Recipient email(s), comma-separated"), subject: z.string().describe("Subject"), body: z.string().describe("Body (plain text)"), cc: z.string().optional().describe("CC email(s), comma-separated"), bcc: z.string().optional().describe("BCC email(s), comma-separated"), importance: z.string().optional().describe("Importance: low, normal, high (default: normal)") },
    async ({ to, subject, body, cc, bcc, importance }) => {
      try {
        const message = {
          subject,
          body: { contentType: "Text", content: body },
          toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
        };
        if (cc) message.ccRecipients = cc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
        if (bcc) message.bccRecipients = bcc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
        if (importance) message.importance = importance;
        await graph("POST", "/me/sendMail", { message, saveToSentItems: true }, userId);
        return { content: [{ type: "text", text: `Email sent to ${to}` }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("reply_email", "Reply to an email",
    { messageId: z.string().describe("Message ID to reply to"), comment: z.string().describe("Reply text") },
    async ({ messageId, comment }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/reply`, { comment }, userId);
        return { content: [{ type: "text", text: "Reply sent" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("reply_all_email", "Reply-all to an email",
    { messageId: z.string().describe("Message ID"), comment: z.string().describe("Reply text") },
    async ({ messageId, comment }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/replyAll`, { comment }, userId);
        return { content: [{ type: "text", text: "Reply-all sent" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("forward_email", "Forward an email",
    { messageId: z.string().describe("Message ID"), to: z.string().describe("Recipient email(s), comma-separated"), comment: z.string().optional().describe("Optional comment") },
    async ({ messageId, to, comment }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/forward`, {
          comment: comment || "",
          toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
        }, userId);
        return { content: [{ type: "text", text: `Email forwarded to ${to}` }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("update_email", "Update email properties (mark read/unread, move, flag)",
    { messageId: z.string().describe("Message ID"), isRead: z.boolean().optional().describe("Mark as read/unread"), flag: z.string().optional().describe("Flag: flagged, notFlagged, complete"), destinationFolderId: z.string().optional().describe("Move to folder ID") },
    async ({ messageId, isRead, flag, destinationFolderId }) => {
      try {
        if (destinationFolderId) {
          await graph("POST", `/me/messages/${messageId}/move`, { destinationId: destinationFolderId }, userId);
        }
        const patch = {};
        if (isRead !== undefined) patch.isRead = isRead;
        if (flag) patch.flag = { flagStatus: flag };
        if (Object.keys(patch).length > 0) {
          await graph("PATCH", `/me/messages/${messageId}`, patch, userId);
        }
        return { content: [{ type: "text", text: "Email updated" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("create_draft", "Create an email draft",
    { to: z.string().describe("Recipient email(s), comma-separated"), subject: z.string().describe("Subject"), body: z.string().describe("Body"), cc: z.string().optional().describe("CC emails, comma-separated"), bcc: z.string().optional().describe("BCC emails, comma-separated") },
    async ({ to, subject, body, cc, bcc }) => {
      try {
        const msg = {
          subject,
          body: { contentType: "Text", content: body },
          toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
        };
        if (cc) msg.ccRecipients = cc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
        if (bcc) msg.bccRecipients = bcc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
        const draft = await graph("POST", "/me/messages", msg, userId);
        return { content: [{ type: "text", text: `Draft created (ID: ${draft.id})` }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("send_draft", "Send an existing draft email",
    { messageId: z.string().describe("Draft message ID") },
    async ({ messageId }) => {
      try {
        await graph("POST", `/me/messages/${messageId}/send`, null, userId);
        return { content: [{ type: "text", text: "Draft sent" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  // ======== ATTACHMENT TOOLS (2) ========

  server.tool("list_attachments", "List all attachments on an email",
    { messageId: z.string().describe("Email message ID") },
    async ({ messageId }) => {
      try {
        const data = await graph("GET", `/me/messages/${messageId}/attachments?$select=id,name,contentType,size`, null, userId);
        const atts = (data.value || []).map(a => `ID: ${a.id}\nName: ${a.name}\nType: ${a.contentType}\nSize: ${a.size} bytes`);
        return { content: [{ type: "text", text: atts.length ? atts.join("\n---\n") : "No attachments" }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("download_attachment", "Download an email attachment (returns base64 content)",
    { messageId: z.string().describe("Email message ID"), attachmentId: z.string().describe("Attachment ID from list_attachments") },
    async ({ messageId, attachmentId }) => {
      try {
        const data = await graph("GET", `/me/messages/${messageId}/attachments/${attachmentId}`, null, userId);
        return { content: [{ type: "text", text: JSON.stringify({ name: data.name, contentType: data.contentType, size: data.size, contentBytes: data.contentBytes }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  // ======== FOLDER MANAGEMENT TOOLS (6) ========

  server.tool("list_child_folders", "List child folders under a parent mail folder with pagination",
    { parentFolderId: z.string().describe("Parent folder ID or well-known name (e.g. inbox)"), top: z.string().optional().describe("Results per page (default: 50, max: 50)"), skip: z.string().optional().describe("Results to skip for pagination (default: 0)"), nameFilter: z.string().optional().describe("Only return folders whose name starts with this prefix (e.g. Project)") },
    async ({ parentFolderId, top, skip, nameFilter }) => {
      try {
        const limit = Math.min(parseInt(top) || 50, 50);
        const offset = parseInt(skip) || 0;
        const filterParam = nameFilter ? `&$filter=startsWith(displayName,'${nameFilter.replace(/'/g, "''")}')` : "";
        const parent = await graph("GET", `/me/mailFolders/${parentFolderId}?$select=childFolderCount`, null, userId);
        const data = await graph("GET", `/me/mailFolders/${parentFolderId}/childFolders?$top=${limit}&$skip=${offset}&$orderby=displayName&$select=id,displayName,totalItemCount,childFolderCount${filterParam}`, null, userId);
        const folders = (data.value || []).map(f => ({ id: f.id, displayName: f.displayName, totalItemCount: f.totalItemCount, childFolderCount: f.childFolderCount }));
        const totalCount = parent.childFolderCount || 0;
        const hasMore = offset + folders.length < totalCount;
        return { content: [{ type: "text", text: JSON.stringify({ folders, totalCount, hasMore }, null, 2) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("get_folder_by_name", "Find a folder by exact display name within a parent folder",
    { parentFolderId: z.string().describe("Parent folder ID or well-known name"), folderName: z.string().describe("Exact display name to match (case-insensitive)") },
    async ({ parentFolderId, folderName }) => {
      try {
        const escaped = folderName.replace(/'/g, "''");
        const data = await graph("GET", `/me/mailFolders/${parentFolderId}/childFolders?$filter=displayName eq '${escaped}'&$select=id,displayName,totalItemCount,childFolderCount`, null, userId);
        if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: JSON.stringify({ found: false, folder: null }) }] };
        const f = data.value[0];
        return { content: [{ type: "text", text: JSON.stringify({ found: true, folder: { id: f.id, displayName: f.displayName, totalItemCount: f.totalItemCount, childFolderCount: f.childFolderCount } }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("create_folder", "Create a new child folder under a parent folder (checks for duplicates first)",
    { parentFolderId: z.string().describe("Parent folder ID"), displayName: z.string().describe("Display name for the new folder (e.g. zArchive)") },
    async ({ parentFolderId, displayName }) => {
      try {
        const escaped = displayName.replace(/'/g, "''");
        const existing = await graph("GET", `/me/mailFolders/${parentFolderId}/childFolders?$filter=displayName eq '${escaped}'&$select=id,displayName`, null, userId);
        if (existing.value && existing.value.length > 0) {
          const f = existing.value[0];
          return { content: [{ type: "text", text: JSON.stringify({ id: f.id, displayName: f.displayName, parentFolderId, created: false }) }] };
        }
        const f = await graph("POST", `/me/mailFolders/${parentFolderId}/childFolders`, { displayName }, userId);
        return { content: [{ type: "text", text: JSON.stringify({ id: f.id, displayName: f.displayName, parentFolderId, created: true }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("rename_folder", "Rename a mail folder",
    { folderId: z.string().describe("Folder ID to rename"), newDisplayName: z.string().describe("New display name") },
    async ({ folderId, newDisplayName }) => {
      try {
        const before = await graph("GET", `/me/mailFolders/${folderId}?$select=id,displayName`, null, userId);
        const previousDisplayName = before.displayName;
        const after = await graph("PATCH", `/me/mailFolders/${folderId}`, { displayName: newDisplayName }, userId);
        return { content: [{ type: "text", text: JSON.stringify({ id: after.id, displayName: after.displayName, previousDisplayName }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("move_folder", "Move a folder and all its contents to a new parent folder",
    { folderId: z.string().describe("Folder ID to move"), destinationFolderId: z.string().describe("Destination parent folder ID") },
    async ({ folderId, destinationFolderId }) => {
      try {
        const result = await graph("POST", `/me/mailFolders/${folderId}/move`, { destinationId: destinationFolderId }, userId);
        return { content: [{ type: "text", text: JSON.stringify({ id: result.id, displayName: result.displayName, parentFolderId: result.parentFolderId }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  server.tool("get_latest_email_in_folder", "Get the most recent email in a folder (activity check for archive workflow)",
    { folderId: z.string().describe("Folder ID to check") },
    async ({ folderId }) => {
      try {
        const folder = await graph("GET", `/me/mailFolders/${folderId}?$select=totalItemCount`, null, userId);
        if (!folder.totalItemCount || folder.totalItemCount === 0) {
          return { content: [{ type: "text", text: JSON.stringify({ hasEmails: false, latestEmail: null, daysSinceLastEmail: null }) }] };
        }
        const data = await graph("GET", `/me/mailFolders/${folderId}/messages?$orderby=receivedDateTime desc&$top=1&$select=id,subject,sender,receivedDateTime`, null, userId);
        if (!data.value || data.value.length === 0) {
          return { content: [{ type: "text", text: JSON.stringify({ hasEmails: false, latestEmail: null, daysSinceLastEmail: null }) }] };
        }
        const m = data.value[0];
        const received = new Date(m.receivedDateTime);
        const daysSince = Math.floor((Date.now() - received.getTime()) / (1000 * 60 * 60 * 24));
        return { content: [{ type: "text", text: JSON.stringify({ hasEmails: true, latestEmail: { id: m.id, subject: m.subject, sender: m.sender?.emailAddress?.address, receivedDateTime: m.receivedDateTime }, daysSinceLastEmail: daysSince }) }] };
      } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
    }
  );

  // ======== ADMIN MAIL TOOLS (10) ========
  // Gated by isAdmin check. Uses app-level token to access /users/{email}/...

  if (isAdmin) {
    server.tool("admin_search_emails", "ADMIN: Search any user's mailbox in the domain",
      { userEmail: z.string().describe("Target user email address"), query: z.string().describe("Search query (KQL syntax)"), folder: z.string().optional().describe("Well-known folder name (default: inbox)"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
      async ({ userEmail: targetEmail, query, folder, top }) => {
        try {
          const token = await getAppToken();
          const f = VALID_FOLDERS.includes(folder) ? folder : "inbox";
          const limit = safeTop(top);
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${f}/messages?$search="${encodeURIComponent(query)}"&$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview,isRead`, null, token);
          if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: `No emails found for ${targetEmail}` }] };
          const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nRead: ${m.isRead}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
          return { content: [{ type: "text", text: `Results for ${targetEmail}:\n\n` + lines.join("\n---\n") }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_search_folder_emails", "ADMIN: Search a specific folder in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), folderId: z.string().describe("Mail folder ID"), query: z.string().optional().describe("Search query (omit to list recent)"), top: z.string().optional().describe("Number of results (default: 10, max: 50)") },
      async ({ userEmail: targetEmail, folderId, query, top }) => {
        try {
          const token = await getAppToken();
          const limit = safeTop(top);
          const searchParam = query ? `$search="${encodeURIComponent(query)}"&` : "";
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}/messages?${searchParam}$top=${limit}&$select=id,subject,from,receivedDateTime,bodyPreview,isRead&$orderby=receivedDateTime desc`, null, token);
          if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: `No emails found for ${targetEmail}` }] };
          const lines = data.value.map((m) => `ID: ${m.id}\nFrom: ${m.from?.emailAddress?.address}\nDate: ${m.receivedDateTime}\nSubject: ${m.subject}\nRead: ${m.isRead}\nPreview: ${m.bodyPreview?.slice(0, 100)}\n`);
          return { content: [{ type: "text", text: `Results for ${targetEmail}:\n\n` + lines.join("\n---\n") }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_read_email", "ADMIN: Read a specific email from any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Message ID") },
      async ({ userEmail: targetEmail, messageId }) => {
        try {
          const token = await getAppToken();
          const m = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,flag,importance`, null, token);
          const to = m.toRecipients?.map((r) => r.emailAddress.address).join(", ");
          const cc = m.ccRecipients?.map((r) => r.emailAddress.address).join(", ");
          const text = [`[Admin — reading on behalf of ${targetEmail}]`, `Subject: ${m.subject}`, `From: ${m.from?.emailAddress?.address}`, `To: ${to}`, cc ? `CC: ${cc}` : null, `Date: ${m.receivedDateTime}`, `Read: ${m.isRead}`, `Flag: ${m.flag?.flagStatus || "none"}`, `Importance: ${m.importance || "normal"}`, ``, stripHtml(m.body?.content)].filter(Boolean).join("\n");
          return { content: [{ type: "text", text }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_send_email", "ADMIN: Send an email from any user's mailbox",
      { userEmail: z.string().describe("Sender user email"), to: z.string().describe("Recipient email(s), comma-separated"), subject: z.string().describe("Subject"), body: z.string().describe("Body (plain text)"), cc: z.string().optional().describe("CC email(s)"), bcc: z.string().optional().describe("BCC email(s)") },
      async ({ userEmail: senderEmail, to, subject, body, cc, bcc }) => {
        try {
          const token = await getAppToken();
          const message = {
            subject,
            body: { contentType: "Text", content: body },
            toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
          };
          if (cc) message.ccRecipients = cc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
          if (bcc) message.bccRecipients = bcc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
          await graphWithToken("POST", `/users/${encodeURIComponent(senderEmail)}/sendMail`, { message, saveToSentItems: true }, token);
          return { content: [{ type: "text", text: `Email sent from ${senderEmail} to ${to}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_reply_email", "ADMIN: Reply to an email in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Message ID"), comment: z.string().describe("Reply text") },
      async ({ userEmail: targetEmail, messageId, comment }) => {
        try {
          const token = await getAppToken();
          await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/reply`, { comment }, token);
          return { content: [{ type: "text", text: `Reply sent on behalf of ${targetEmail}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_reply_all_email", "ADMIN: Reply-all to an email in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Message ID"), comment: z.string().describe("Reply text") },
      async ({ userEmail: targetEmail, messageId, comment }) => {
        try {
          const token = await getAppToken();
          await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/replyAll`, { comment }, token);
          return { content: [{ type: "text", text: `Reply-all sent on behalf of ${targetEmail}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_forward_email", "ADMIN: Forward an email from any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Message ID"), to: z.string().describe("Recipient email(s), comma-separated"), comment: z.string().optional().describe("Optional comment") },
      async ({ userEmail: targetEmail, messageId, to, comment }) => {
        try {
          const token = await getAppToken();
          await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/forward`, {
            comment: comment || "",
            toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
          }, token);
          return { content: [{ type: "text", text: `Email forwarded from ${targetEmail} to ${to}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_update_email", "ADMIN: Update email properties in any user's mailbox (read/unread, flag, move)",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Message ID"), isRead: z.boolean().optional().describe("Mark as read/unread"), flag: z.string().optional().describe("Flag: flagged, notFlagged, complete"), destinationFolderId: z.string().optional().describe("Move to folder ID") },
      async ({ userEmail: targetEmail, messageId, isRead, flag, destinationFolderId }) => {
        try {
          const token = await getAppToken();
          if (destinationFolderId) {
            await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/move`, { destinationId: destinationFolderId }, token);
          }
          const patch = {};
          if (isRead !== undefined) patch.isRead = isRead;
          if (flag) patch.flag = { flagStatus: flag };
          if (Object.keys(patch).length > 0) {
            await graphWithToken("PATCH", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}`, patch, token);
          }
          return { content: [{ type: "text", text: `Email updated for ${targetEmail}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_create_draft", "ADMIN: Create a draft in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), to: z.string().describe("Recipient email(s), comma-separated"), subject: z.string().describe("Subject"), body: z.string().describe("Body"), cc: z.string().optional().describe("CC emails"), bcc: z.string().optional().describe("BCC emails") },
      async ({ userEmail: targetEmail, to, subject, body, cc, bcc }) => {
        try {
          const token = await getAppToken();
          const msg = {
            subject,
            body: { contentType: "Text", content: body },
            toRecipients: to.split(",").map((e) => ({ emailAddress: { address: e.trim() } })),
          };
          if (cc) msg.ccRecipients = cc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
          if (bcc) msg.bccRecipients = bcc.split(",").map((e) => ({ emailAddress: { address: e.trim() } }));
          const draft = await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages`, msg, token);
          return { content: [{ type: "text", text: `Draft created for ${targetEmail} (ID: ${draft.id})` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_send_draft", "ADMIN: Send a draft from any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Draft message ID") },
      async ({ userEmail: targetEmail, messageId }) => {
        try {
          const token = await getAppToken();
          await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/send`, null, token);
          return { content: [{ type: "text", text: `Draft sent from ${targetEmail}` }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    // ======== ADMIN ATTACHMENT TOOLS (2) ========

    server.tool("admin_list_attachments", "ADMIN: List all attachments on an email in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Email message ID") },
      async ({ userEmail: targetEmail, messageId }) => {
        try {
          const token = await getAppToken();
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/attachments?$select=id,name,contentType,size`, null, token);
          const atts = (data.value || []).map(a => `ID: ${a.id}\nName: ${a.name}\nType: ${a.contentType}\nSize: ${a.size} bytes`);
          return { content: [{ type: "text", text: atts.length ? atts.join("\n---\n") : "No attachments" }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_download_attachment", "ADMIN: Download an attachment from any user's mailbox (returns base64 content)",
      { userEmail: z.string().describe("Target user email"), messageId: z.string().describe("Email message ID"), attachmentId: z.string().describe("Attachment ID from admin_list_attachments") },
      async ({ userEmail: targetEmail, messageId, attachmentId }) => {
        try {
          const token = await getAppToken();
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/messages/${messageId}/attachments/${attachmentId}`, null, token);
          return { content: [{ type: "text", text: JSON.stringify({ name: data.name, contentType: data.contentType, size: data.size, contentBytes: data.contentBytes }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );
    // ======== ADMIN FOLDER MANAGEMENT TOOLS (6) ========

    server.tool("admin_list_child_folders", "ADMIN: List child folders under a parent folder in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), parentFolderId: z.string().describe("Parent folder ID or well-known name (e.g. inbox)"), top: z.string().optional().describe("Results per page (default: 50, max: 50)"), skip: z.string().optional().describe("Results to skip for pagination (default: 0)"), nameFilter: z.string().optional().describe("Only return folders whose name starts with this prefix (e.g. Project)") },
      async ({ userEmail: targetEmail, parentFolderId, top, skip, nameFilter }) => {
        try {
          const token = await getAppToken();
          const limit = Math.min(parseInt(top) || 50, 50);
          const offset = parseInt(skip) || 0;
          const filterParam = nameFilter ? `&$filter=startsWith(displayName,'${nameFilter.replace(/'/g, "''")}')` : "";
          const parent = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${parentFolderId}?$select=childFolderCount`, null, token);
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${parentFolderId}/childFolders?$top=${limit}&$skip=${offset}&$orderby=displayName&$select=id,displayName,totalItemCount,childFolderCount${filterParam}`, null, token);
          const folders = (data.value || []).map(f => ({ id: f.id, displayName: f.displayName, totalItemCount: f.totalItemCount, childFolderCount: f.childFolderCount }));
          const totalCount = parent.childFolderCount || 0;
          const hasMore = offset + folders.length < totalCount;
          return { content: [{ type: "text", text: JSON.stringify({ folders, totalCount, hasMore }, null, 2) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_get_folder_by_name", "ADMIN: Find a folder by exact name in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), parentFolderId: z.string().describe("Parent folder ID or well-known name"), folderName: z.string().describe("Exact display name to match (case-insensitive)") },
      async ({ userEmail: targetEmail, parentFolderId, folderName }) => {
        try {
          const token = await getAppToken();
          const escaped = folderName.replace(/'/g, "''");
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${parentFolderId}/childFolders?$filter=displayName eq '${escaped}'&$select=id,displayName,totalItemCount,childFolderCount`, null, token);
          if (!data.value || data.value.length === 0) return { content: [{ type: "text", text: JSON.stringify({ found: false, folder: null }) }] };
          const f = data.value[0];
          return { content: [{ type: "text", text: JSON.stringify({ found: true, folder: { id: f.id, displayName: f.displayName, totalItemCount: f.totalItemCount, childFolderCount: f.childFolderCount } }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_create_folder", "ADMIN: Create a child folder in any user's mailbox (checks for duplicates first)",
      { userEmail: z.string().describe("Target user email"), parentFolderId: z.string().describe("Parent folder ID"), displayName: z.string().describe("Display name for the new folder") },
      async ({ userEmail: targetEmail, parentFolderId, displayName }) => {
        try {
          const token = await getAppToken();
          const escaped = displayName.replace(/'/g, "''");
          const existing = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${parentFolderId}/childFolders?$filter=displayName eq '${escaped}'&$select=id,displayName`, null, token);
          if (existing.value && existing.value.length > 0) {
            const f = existing.value[0];
            return { content: [{ type: "text", text: JSON.stringify({ id: f.id, displayName: f.displayName, parentFolderId, created: false }) }] };
          }
          const f = await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${parentFolderId}/childFolders`, { displayName }, token);
          return { content: [{ type: "text", text: JSON.stringify({ id: f.id, displayName: f.displayName, parentFolderId, created: true }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_rename_folder", "ADMIN: Rename a mail folder in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), folderId: z.string().describe("Folder ID to rename"), newDisplayName: z.string().describe("New display name") },
      async ({ userEmail: targetEmail, folderId, newDisplayName }) => {
        try {
          const token = await getAppToken();
          const before = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}?$select=id,displayName`, null, token);
          const previousDisplayName = before.displayName;
          const after = await graphWithToken("PATCH", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}`, { displayName: newDisplayName }, token);
          return { content: [{ type: "text", text: JSON.stringify({ id: after.id, displayName: after.displayName, previousDisplayName }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_move_folder", "ADMIN: Move a folder in any user's mailbox to a new parent",
      { userEmail: z.string().describe("Target user email"), folderId: z.string().describe("Folder ID to move"), destinationFolderId: z.string().describe("Destination parent folder ID") },
      async ({ userEmail: targetEmail, folderId, destinationFolderId }) => {
        try {
          const token = await getAppToken();
          const result = await graphWithToken("POST", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}/move`, { destinationId: destinationFolderId }, token);
          return { content: [{ type: "text", text: JSON.stringify({ id: result.id, displayName: result.displayName, parentFolderId: result.parentFolderId }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

    server.tool("admin_get_latest_email_in_folder", "ADMIN: Get the most recent email in a folder in any user's mailbox",
      { userEmail: z.string().describe("Target user email"), folderId: z.string().describe("Folder ID to check") },
      async ({ userEmail: targetEmail, folderId }) => {
        try {
          const token = await getAppToken();
          const folder = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}?$select=totalItemCount`, null, token);
          if (!folder.totalItemCount || folder.totalItemCount === 0) {
            return { content: [{ type: "text", text: JSON.stringify({ hasEmails: false, latestEmail: null, daysSinceLastEmail: null }) }] };
          }
          const data = await graphWithToken("GET", `/users/${encodeURIComponent(targetEmail)}/mailFolders/${folderId}/messages?$orderby=receivedDateTime desc&$top=1&$select=id,subject,sender,receivedDateTime`, null, token);
          if (!data.value || data.value.length === 0) {
            return { content: [{ type: "text", text: JSON.stringify({ hasEmails: false, latestEmail: null, daysSinceLastEmail: null }) }] };
          }
          const m = data.value[0];
          const received = new Date(m.receivedDateTime);
          const daysSince = Math.floor((Date.now() - received.getTime()) / (1000 * 60 * 60 * 24));
          return { content: [{ type: "text", text: JSON.stringify({ hasEmails: true, latestEmail: { id: m.id, subject: m.subject, sender: m.sender?.emailAddress?.address, receivedDateTime: m.receivedDateTime }, daysSinceLastEmail: daysSince }) }] };
        } catch (e) { return { content: [{ type: "text", text: `Error: ${e.message}` }] }; }
      }
    );

  } // end admin tools

  return server;
}

// ============================================================
// Express App
// ============================================================
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: false } }));

// Fix 14: Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Fix 6: CORS restricted to Claude.ai
app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "https://claude.ai");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PATCH");
  res.set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version");
  res.set("Access-Control-Expose-Headers", "WWW-Authenticate");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// --- Health / Metadata ---
app.get("/", (req, res) => res.json({ status: "ok", service: "essa-outlook-email", version: "1.0.0" }));

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

// --- Fix 2: DCR with persistent storage ---
app.post("/oauth/register", async (req, res) => {
  const clientId = randomBytes(16).toString("hex");
  const clientName = req.body.client_name || "Claude";
  const redirectUris = JSON.stringify(req.body.redirect_uris || []);
  try {
    await pool.query("INSERT INTO registered_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3)", [clientId, clientName, redirectUris]);
  } catch (e) {
    console.error("DCR storage error:", e);
  }
  console.log(`DCR: Registered "${clientName}" -> ${clientId}`);
  res.status(201).json({
    client_id: clientId,
    client_name: clientName,
    redirect_uris: req.body.redirect_uris || [],
    grant_types: req.body.grant_types || ["authorization_code"],
    response_types: req.body.response_types || ["code"],
    token_endpoint_auth_method: req.body.token_endpoint_auth_method || "none",
  });
});

// --- OAuth Authorize ---
app.get("/oauth/authorize", async (req, res) => {
  const { redirect_uri, state, code_challenge, client_id } = req.query;
  if (!redirect_uri || !state) return res.status(400).send("Missing redirect_uri or state");

  // Fix 3: Whitelist redirect_uris
  if (!ALLOWED_REDIRECT_URIS.includes(redirect_uri)) {
    console.warn(`Rejected redirect_uri: ${redirect_uri}`);
    return res.status(400).send("Invalid redirect_uri");
  }

  // Fix 2: Validate client_id
  if (client_id) {
    const clientRow = await pool.query("SELECT client_id FROM registered_clients WHERE client_id = $1", [client_id]);
    if (clientRow.rows.length === 0) {
      return res.status(400).send("Unknown client_id");
    }
  }

  try {
    await pool.query(
      "INSERT INTO pending_auth (state, redirect_uri, code_challenge) VALUES ($1, $2, $3) ON CONFLICT (state) DO UPDATE SET redirect_uri=$2, code_challenge=$3, created_at=NOW()",
      [state, redirect_uri, code_challenge || null]
    );
  } catch (e) {
    console.error("Failed to save pending_auth:", e);
    return res.status(500).send("Server error");
  }
  const params = new URLSearchParams({
    client_id: CLIENT_ID, response_type: "code", redirect_uri: MS_REDIRECT_URI,
    scope: SCOPES.join(" "), state, response_mode: "query",
  });
  res.redirect(`https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`);
});

// --- MS OAuth Callback ---
app.get("/oauth/ms-callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(`Microsoft auth error: ${error}`);
  if (!code || !state) return res.status(400).send("Missing code or state");
  try {
    const pending = await pool.query("SELECT redirect_uri, code_challenge FROM pending_auth WHERE state = $1", [state]);
    if (pending.rows.length === 0) return res.status(400).send("Invalid or expired state");
    const { redirect_uri } = pending.rows[0];
    const msalApp = createMsalApp();
    const result = await msalApp.acquireTokenByCode({ code, scopes: SCOPES, redirectUri: MS_REDIRECT_URI });
    const userId = result.account.homeAccountId;
    const userEmail = result.account.username;
    const cacheData = encrypt(msalApp.getTokenCache().serialize());
    await pool.query(
      `INSERT INTO user_tokens (user_id, user_email, token_cache) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET user_email=$2, token_cache=$3, updated_at=NOW()`,
      [userId, userEmail, cacheData]
    );
    // Fix 9: Store user_id in pending_auth
    const ourAuthCode = randomBytes(32).toString("hex");
    await pool.query("UPDATE pending_auth SET our_auth_code = $1, user_id = $2 WHERE state = $3", [ourAuthCode, userId, state]);
    const callbackParams = new URLSearchParams({ code: ourAuthCode, state });
    res.redirect(`${redirect_uri}?${callbackParams.toString()}`);
  } catch (e) {
    console.error("OAuth MS callback error:", e);
    res.status(500).send(`Auth failed: ${e.message}`);
  }
});

// --- Token Exchange ---
app.post("/oauth/token", async (req, res) => {
  const { grant_type, code, code_verifier } = req.body;
  if (grant_type !== "authorization_code") return res.status(400).json({ error: "unsupported_grant_type" });
  if (!code) return res.status(400).json({ error: "missing code" });
  try {
    const pending = await pool.query("SELECT state, code_challenge, user_id FROM pending_auth WHERE our_auth_code = $1", [code]);
    if (pending.rows.length === 0) return res.status(400).json({ error: "invalid_grant" });
    const { state, code_challenge, user_id: pendingUserId } = pending.rows[0];

    // Fix 8: Enforce PKCE when code_challenge was provided
    if (!verifyPKCE(code_verifier, code_challenge)) {
      return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
    }

    // Fix 9: Read user_id directly from pending_auth
    if (!pendingUserId) return res.status(400).json({ error: "invalid_grant", error_description: "User not found" });

    const accessToken = randomBytes(48).toString("hex");
    await pool.query("INSERT INTO mcp_sessions (access_token, user_id) VALUES ($1, $2)", [accessToken, pendingUserId]);
    await pool.query("DELETE FROM pending_auth WHERE state = $1", [state]);
    res.json({ access_token: accessToken, token_type: "bearer", expires_in: SESSION_TTL_HOURS * 3600 });
  } catch (e) {
    console.error("Token exchange error:", e);
    res.status(500).json({ error: "server_error", error_description: e.message });
  }
});

// --- Main MCP Endpoint (OAuth-protected) ---
app.all("/mcp", async (req, res) => {
  const authHeader = req.headers.authorization || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
  const wwwAuth = `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`;
  if (!bearerToken) {
    res.set("WWW-Authenticate", wwwAuth);
    return res.status(401).json({ error: "unauthorized" });
  }
  // Fix 7: Check session expiry
  const sessionRow = await pool.query(
    `SELECT user_id FROM mcp_sessions WHERE access_token = $1 AND created_at > NOW() - INTERVAL '${SESSION_TTL_HOURS} hours'`,
    [bearerToken]
  );
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

// --- Legacy per-user MCP Endpoint ---
// Fix 1: Requires MCP_API_KEY header. Disabled if env var not set.
app.all("/mcp/:userId", async (req, res) => {
  if (!MCP_API_KEY) return res.status(404).json({ error: "Not found" });
  const apiKey = req.headers["x-api-key"];
  if (apiKey !== MCP_API_KEY) return res.status(401).json({ error: "Invalid API key" });

  const { userId } = req.params;
  const row = await pool.query("SELECT user_id, user_email FROM user_tokens WHERE user_id = $1", [userId]);
  if (row.rows.length === 0) return res.status(401).json({ error: "User not authenticated" });
  const userEmail = row.rows[0].user_email;
  const server = createMcpServer(userId, userEmail);
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// --- Legacy Browser Auth ---
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
    const cacheData = encrypt(msalApp.getTokenCache().serialize());
    await pool.query(
      `INSERT INTO user_tokens (user_id, user_email, token_cache) VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE SET user_email=$2, token_cache=$3, updated_at=NOW()`,
      [userId, userEmail, cacheData]
    );
    req.session.userId = userId;
    const mcpUrl = `${BASE_URL}/mcp/${userId}`;
    const safeEmail = escapeHtml(userEmail);
    const safeMcpUrl = escapeHtml(mcpUrl);
    const configJson = escapeHtml(JSON.stringify({ mcpServers: { "essa-outlook-email": { url: mcpUrl } } }, null, 2));
    res.send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ESSA Custom MCP - Outlook_eMail - Setup Complete</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:740px;margin:40px auto;padding:0 24px;color:#1a1a1a;line-height:1.6}h1{color:#2e7d32}h2{margin-top:2em;border-bottom:1px solid #e0e0e0;padding-bottom:4px}code{background:#f5f5f5;padding:2px 6px;border-radius:3px;font-size:.88em;word-break:break-all}pre{background:#f5f5f5;border:1px solid #ddd;padding:16px;border-radius:6px;overflow-x:auto;font-size:.85em;line-height:1.55}.step{margin:.8em 0 .8em 1.2em}.note{background:#fff8e1;border-left:4px solid #f9a825;padding:12px 16px;border-radius:3px;margin:1.2em 0;font-size:.92em}.footer{margin-top:3em;color:#888;font-size:.82em;border-top:1px solid #eee;padding-top:1em}</style></head>
<body>
<h1>Authenticated Successfully</h1>
<p>Signed in as: <strong>${safeEmail}</strong></p>
<h2>Step 1 - Your personal MCP endpoint</h2>
<pre>${safeMcpUrl}</pre>
<h2>Step 2 - Add to Claude Desktop</h2>
<p>Open the Claude Desktop config file at:</p>
<div class="step"><strong>Windows:</strong> <code>%APPDATA%\\Claude\\claude_desktop_config.json</code></div>
<div class="step"><strong>Mac:</strong> <code>~/Library/Application Support/Claude/claude_desktop_config.json</code></div>
<p>Paste the following:</p>
<pre>${configJson}</pre>
<div class="note"><strong>Tip:</strong> If the file already has an <code>mcpServers</code> block, just add the <code>"essa-outlook-email"</code> entry inside it.</div>
<h2>Step 3 - Restart Claude Desktop</h2>
<div class="step">1. Save the config file.</div>
<div class="step">2. Quit Claude Desktop completely and reopen it.</div>
<div class="step">3. Look for <strong>essa-outlook-email</strong> tools via the hammer icon.</div>
<div class="footer">Do not share this endpoint. <a href="/auth/login">Re-authenticate</a></div>
</body></html>`);
  } catch (e) {
    res.status(500).send(`Callback error: ${e.message}`);
  }
});

// Fix 12: Global error handler
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "internal_server_error" });
});

// Fix 13: Block startup until DB is initialised
(async () => {
  try {
    await initDb();
    console.log("DB initialised");
  } catch (err) {
    console.error("DB init failed:", err);
    process.exit(1);
  }
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ESSA Custom MCP - Outlook_eMail v1.0.0 listening on 0.0.0.0:${PORT}`);
    console.log(`Connector: ${BASE_URL}/mcp`);
    console.log(`DCR: ${BASE_URL}/oauth/register`);
    console.log(`ENV: DB=${!!process.env.DATABASE_URL} CLIENT=${!!CLIENT_ID} TENANT=${!!TENANT_ID} SECRET=${!!CLIENT_SECRET} ENCRYPTION=${!!TOKEN_ENCRYPTION_KEY}`);
  });
})();
