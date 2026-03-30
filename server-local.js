import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { PublicClientApplication } from "@azure/msal-node";
import fetch from "node-fetch";
import { z } from "zod";
import fs from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Config — fill in your Azure app details
// ---------------------------------------------------------------------------
const CLIENT_ID = process.env.AZURE_CLIENT_ID;
const TENANT_ID = process.env.AZURE_TENANT_ID;
const TOKEN_CACHE_FILE = path.join(process.env.APPDATA || ".", "mcp-outlook-token.json");

const msalApp = new PublicClientApplication({
  auth: {
    clientId: CLIENT_ID,
    authority: `https://login.microsoftonline.com/${TENANT_ID}`,
  },
  cache: {
    cachePlugin: {
      beforeCacheAccess: async (ctx) => {
        if (fs.existsSync(TOKEN_CACHE_FILE)) {
          ctx.tokenCache.deserialize(fs.readFileSync(TOKEN_CACHE_FILE, "utf8"));
        }
      },
      afterCacheAccess: async (ctx) => {
        if (ctx.cacheHasChanged) {
          fs.writeFileSync(TOKEN_CACHE_FILE, ctx.tokenCache.serialize());
        }
      },
    },
  },
});

// ---------------------------------------------------------------------------
// Auth helper — device code flow
// ---------------------------------------------------------------------------
async function getToken() {
  const scopes = ["Mail.ReadWrite", "offline_access"];

  const accounts = await msalApp.getTokenCache().getAllAccounts();
  if (accounts.length > 0) {
    try {
      const result = await msalApp.acquireTokenSilent({ scopes, account: accounts[0] });
      return result.accessToken;
    } catch (_) { /* fall through to device code */ }
  }

  const deviceCodeResponse = await msalApp.acquireTokenByDeviceCode({
    scopes,
    deviceCodeCallback: (response) => {
      process.stderr.write(`\n[AUTH REQUIRED] Open ${response.verificationUri} and enter code: ${response.userCode}\n`);
    },
  });
  return deviceCodeResponse.accessToken;
}

// ---------------------------------------------------------------------------
// Graph API helper
// ---------------------------------------------------------------------------
async function graph(method, path, body) {
  const token = await getToken();
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
    throw new Error(`Graph API ${method} ${path} → ${res.status}: ${err}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function getAllChildFolders(folderId) {
  let url = `/me/mailFolders/${folderId}/childFolders?$top=100`;
  const folders = [];
  while (url) {
    const data = await graph("GET", url);
    folders.push(...data.value);
    url = data["@odata.nextLink"]?.replace("https://graph.microsoft.com/v1.0", "") ?? null;
  }
  return folders;
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------
const server = new McpServer({
  name: "mcp-outlook",
  version: "1.0.0",
});

// Tool: list_project_folders
server.tool(
  "list_project_folders",
  "List all Project [NAME] subfolders under Inbox > Deals, showing whether each has been active in the last 2 months",
  {},
  async () => {
    const inbox = await graph("GET", "/me/mailFolders/Inbox");
    const inboxChildren = await getAllChildFolders(inbox.id);
    const deals = inboxChildren.find(f => f.displayName === "Deals");
    if (!deals) throw new Error("Could not find 'Deals' folder under Inbox");

    const subfolders = await getAllChildFolders(deals.id);
    const projectFolders = subfolders.filter(f => f.displayName.startsWith("Project "));

    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - 2);

    const results = await Promise.all(projectFolders.map(async (folder) => {
      const msgs = await graph("GET",
        `/me/mailFolders/${folder.id}/messages?$filter=receivedDateTime ge ${cutoff.toISOString()}&$top=1&$select=receivedDateTime`
      );
      return {
        id: folder.id,
        name: folder.displayName,
        totalEmails: folder.totalItemCount,
        activeLastTwoMonths: msgs.value.length > 0,
        alreadyArchived: folder.displayName.endsWith("- Archive"),
      };
    }));

    return {
      content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
    };
  }
);

// Tool: rename_mail_folder
server.tool(
  "rename_mail_folder",
  "Rename an Outlook mail folder by its ID",
  { folderId: z.string(), newName: z.string() },
  async ({ folderId, newName }) => {
    await graph("PATCH", `/me/mailFolders/${folderId}`, { displayName: newName });
    return {
      content: [{ type: "text", text: `Folder renamed to "${newName}"` }],
    };
  }
);

// Tool: archive_inactive_project_folders
server.tool(
  "archive_inactive_project_folders",
  "Check all Project folders under Inbox > Deals and rename inactive ones (no email in last 2 months) to 'Project [NAME] - Archive'. Skips folders already ending in '- Archive'.",
  { dryRun: z.coerce.boolean().default(true) },
  async ({ dryRun }) => {
    const inbox = await graph("GET", "/me/mailFolders/Inbox");
    const inboxChildren = await getAllChildFolders(inbox.id);
    const deals = inboxChildren.find(f => f.displayName === "Deals");
    if (!deals) throw new Error("Could not find 'Deals' folder under Inbox");

    const subfolders = await getAllChildFolders(deals.id);
    const projectFolders = subfolders.filter(f =>
      f.displayName.startsWith("Project ") &&
      !f.displayName.endsWith("- Archive")
    );

    const cutoff = new Date();
    cutoff.setMonth(cutoff.getMonth() - 2);

    const archived = [];
    const active = [];

    for (const folder of projectFolders) {
      const msgs = await graph("GET",
        `/me/mailFolders/${folder.id}/messages?$filter=receivedDateTime ge ${cutoff.toISOString()}&$top=1&$select=receivedDateTime`
      );

      if (msgs.value.length > 0) {
        active.push(folder.displayName);
      } else {
        const newName = `${folder.displayName} - Archive`;
        if (!dryRun) {
          await graph("PATCH", `/me/mailFolders/${folder.id}`, { displayName: newName });
        }
        archived.push({ from: folder.displayName, to: newName });
      }
    }

    return {
      content: [{
        type: "text", text: JSON.stringify({
          dryRun,
          activeCount: active.length,
          archivedCount: archived.length,
          activeFolders: active,
          renamedFolders: archived,
        }, null, 2)
      }],
    };
  }
);


// Tool: move_mail_folder
server.tool(
  "move_mail_folder",
  "Move an Outlook mail folder into a different parent folder. Accepts folder IDs or well-known names (e.g. 'inbox', 'archive', 'deleteditems', 'sentitems'). Use list_project_folders to get folder IDs.",
  { folderId: z.string(), destinationId: z.string() },
  async ({ folderId, destinationId }) => {
    const result = await graph("POST", `/me/mailFolders/${folderId}/move`, { destinationId });
    return {
      content: [{ type: "text", text: JSON.stringify({
        success: true,
        movedFolder: result.displayName,
        newId: result.id,
        parentFolderId: result.parentFolderId,
      }, null, 2) }],
    };
  }
);

// Tool: archive_and_move_inactive_projects
server.tool(
  "archive_and_move_inactive_projects",
  "Finds all Project [NAME] folders under Inbox > Deals with no email activity in the last 6 weeks. Renames each to 'Project [NAME] - archive' and moves it into Inbox > Deals > zArchive. Creates zArchive if it does not exist. Supports dryRun (default true).",
  { dryRun: z.coerce.boolean().default(true) },
  async ({ dryRun }) => {
    // Locate Inbox > Deals
    const inbox = await graph("GET", "/me/mailFolders/Inbox");
    const inboxChildren = await getAllChildFolders(inbox.id);
    const deals = inboxChildren.find(f => f.displayName === "Deals");
    if (!deals) throw new Error("Could not find 'Deals' folder under Inbox");

    // Locate or create Deals > zArchive
    const dealsChildren = await getAllChildFolders(deals.id);
    let zArchive = dealsChildren.find(f => f.displayName === "zArchive");
    if (!zArchive) {
      if (!dryRun) {
        zArchive = await graph("POST", `/me/mailFolders/${deals.id}/childFolders`, { displayName: "zArchive" });
      } else {
        zArchive = { id: "zArchive-would-be-created", displayName: "zArchive" };
      }
    }

    // 6-week cutoff
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 42);

    // Filter to active Project folders not already archived
    const projectFolders = dealsChildren.filter(f =>
      f.displayName.startsWith("Project ") &&
      !f.displayName.endsWith("- archive") &&
      !f.displayName.endsWith("- Archive")
    );

    const toArchive = [];
    const active = [];

    for (const folder of projectFolders) {
      const msgs = await graph("GET",
        `/me/mailFolders/${folder.id}/messages?$filter=receivedDateTime ge ${cutoff.toISOString()}&$top=1&$select=receivedDateTime`
      );

      if (msgs.value.length > 0) {
        active.push(folder.displayName);
      } else {
        const newName = `${folder.displayName} - archive`;
        if (!dryRun) {
          // Step 1: rename
          await graph("PATCH", `/me/mailFolders/${folder.id}`, { displayName: newName });
          // Step 2: move to zArchive
          await graph("POST", `/me/mailFolders/${folder.id}/move`, { destinationId: zArchive.id });
        }
        toArchive.push({ from: folder.displayName, to: newName, destination: "Inbox/Deals/zArchive" });
      }
    }

    return {
      content: [{ type: "text", text: JSON.stringify({
        dryRun,
        cutoffDate: cutoff.toISOString().split("T")[0],
        zArchiveCreated: !dealsChildren.find(f => f.displayName === "zArchive") && !dryRun,
        activeCount: active.length,
        archivedCount: toArchive.length,
        activeFolders: active,
        archivedFolders: toArchive,
      }, null, 2) }],
    };
  }
);

// Tool: run_archive_and_move
server.tool(
  "run_archive_and_move",
  "LIVE run (no dry run): renames all Project folders under Inbox > Deals with no email in the last 6 weeks to 'Project [NAME] - archive' and moves them to Inbox > Deals > zArchive. Creates zArchive if needed.",
  {},
  async () => {
    const inbox = await graph("GET", "/me/mailFolders/Inbox");
    const inboxChildren = await getAllChildFolders(inbox.id);
    const deals = inboxChildren.find(f => f.displayName === "Deals");
    if (!deals) throw new Error("Could not find 'Deals' folder under Inbox");

    const dealsChildren = await getAllChildFolders(deals.id);
    let zArchive = dealsChildren.find(f => f.displayName === "zArchive");
    const zArchiveCreated = !zArchive;
    if (!zArchive) {
      zArchive = await graph("POST", `/me/mailFolders/${deals.id}/childFolders`, { displayName: "zArchive" });
    }

    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 42);

    const projectFolders = dealsChildren.filter(f =>
      f.displayName.startsWith("Project ") &&
      !f.displayName.endsWith("- archive") &&
      !f.displayName.endsWith("- Archive")
    );

    const archived = [];
    const active = [];

    for (const folder of projectFolders) {
      const msgs = await graph("GET",
        `/me/mailFolders/${folder.id}/messages?$filter=receivedDateTime ge ${cutoff.toISOString()}&$top=1&$select=receivedDateTime`
      );

      if (msgs.value.length > 0) {
        active.push(folder.displayName);
      } else {
        const newName = `${folder.displayName} - archive`;
        await graph("PATCH", `/me/mailFolders/${folder.id}`, { displayName: newName });
        await graph("POST", `/me/mailFolders/${folder.id}/move`, { destinationId: zArchive.id });
        archived.push({ from: folder.displayName, to: newName, destination: "Inbox/Deals/zArchive" });
      }
    }

    return {
      content: [{ type: "text", text: JSON.stringify({
        cutoffDate: cutoff.toISOString().split("T")[0],
        zArchiveCreated,
        activeCount: active.length,
        archivedCount: archived.length,
        activeFolders: active,
        archivedFolders: archived,
      }, null, 2) }],
    };
  }
);
// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const transport = new StdioServerTransport();
await server.connect(transport);
