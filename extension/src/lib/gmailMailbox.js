/**
 * List and fetch Gmail messages for the Receive → Your mailbox tab.
 */

import { extractSdsCiphertext } from "./lit";

export { extractSdsCiphertext };

function headerValue(headers, name) {
  const want = String(name || "").toLowerCase();
  const hit = (headers || []).find(
    (h) => String(h.name || "").toLowerCase() === want,
  );
  return hit?.value || "";
}

function decodeBase64Url(data) {
  if (!data) return "";
  const b64 = String(data).replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  try {
    return decodeURIComponent(
      Array.from(atob(b64 + pad))
        .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
        .join(""),
    );
  } catch {
    try {
      return atob(b64 + pad);
    } catch {
      return "";
    }
  }
}

function decodeBase64UrlBytes(data) {
  if (!data) return new Uint8Array(0);
  const b64 = String(data).replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function walkParts(part, acc = { texts: [], htmls: [], attachments: [] }) {
  if (!part) return acc;
  const mime = String(part.mimeType || "").toLowerCase();
  const filename = part.filename || "";
  const body = part.body || {};

  if (filename && body.attachmentId) {
    acc.attachments.push({
      filename,
      mimeType: mime,
      attachmentId: body.attachmentId,
      size: body.size || 0,
    });
  } else if (body.data) {
    if (mime === "text/plain") acc.texts.push(decodeBase64Url(body.data));
    else if (mime === "text/html") acc.htmls.push(decodeBase64Url(body.data));
    else if (filename) {
      acc.attachments.push({
        filename,
        mimeType: mime,
        bytes: decodeBase64UrlBytes(body.data),
        size: body.size || 0,
      });
    }
  }

  for (const child of part.parts || []) walkParts(child, acc);
  return acc;
}

function isSecureAttachmentName(name) {
  const n = String(name || "").toLowerCase();
  return (
    n.endsWith(".securepdf") ||
    n.endsWith(".securemsg") ||
    n.endsWith(".sdsb") ||
    n.includes("secure-package")
  );
}

function isReplyOrForwardMessage(headers) {
  if (
    headerValue(headers, "In-Reply-To") ||
    headerValue(headers, "References")
  ) {
    return true;
  }
  const subject = headerValue(headers, "Subject") || "";
  return /^(re|fw|fwd)\s*:/i.test(subject.trim());
}

/** Remove quoted reply/forward content so keyword matches aren't from the original mail. */
function stripQuotedReplyContent(text, html) {
  let plain = String(text || "");
  let fromHtml = String(html || "");

  fromHtml = fromHtml
    .replace(/<blockquote[\s\S]*?<\/blockquote>/gi, " ")
    .replace(/<div[^>]*class="[^"]*gmail_quote[^"]*"[\s\S]*$/gi, " ")
    .replace(/<div[^>]*class="[^"]*gmail_extra[^"]*"[\s\S]*$/gi, " ")
    .replace(/<div[^>]*class="[^"]*gmail_attr[^"]*"[\s\S]*$/gi, " ");

  plain = plain
    // "On Mon, ... wrote:" and everything after
    .replace(/\nOn .+wrote:\s*[\s\S]*$/i, "\n")
    // Outlook-style "-----Original Message-----"
    .replace(/\n-+\s*Original Message\s*-+[\s\S]*$/i, "\n")
    // Quoted lines
    .replace(/^\s*>.*$/gm, "");

  const htmlPlain = stripHtml(fromHtml);
  return `${plain}\n${htmlPlain}`.replace(/\s+/g, " ").trim();
}

function isOriginalSecureDocShareMail({
  headers,
  bodyText,
  bodyHtml,
  attachments,
}) {
  const ownBody = stripQuotedReplyContent(bodyText, bodyHtml);
  const secureAttachments = (attachments || []).filter((a) =>
    isSecureAttachmentName(a.filename),
  );
  const ownCiphertext = extractSdsCiphertext(ownBody);

  // Real SDS payload or secure file on this message itself.
  if (ownCiphertext || secureAttachments.length > 0) {
    // Still drop pure replies that only quote ciphertext with no attachment of their own
    // if the sds token exists only because quote stripping failed — handled below.
    if (!isReplyOrForwardMessage(headers)) return true;
    // Replies: allow only if they include their own secure attachment,
    // or a ciphertext that is clearly in the non-quoted body (ownCiphertext already from stripped body).
    if (secureAttachments.length > 0) return true;
    if (ownCiphertext && ownBody.length > 40) return true;
    return false;
  }

  // Keyword-only match: never for replies/forwards.
  if (isReplyOrForwardMessage(headers)) return false;

  return (
    /SecureDocShare/i.test(ownBody) ||
    /ciphertext/i.test(ownBody) ||
    /\bsds\./i.test(ownBody)
  );
}

async function gmailFetch(accessToken, path) {
  const res = await fetch(`https://gmail.googleapis.com/gmail/v1/${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    const err = new Error(
      `Gmail API failed (${res.status}): ${errBody || res.statusText}`,
    );
    err.status = res.status;
    throw err;
  }
  return res.json();
}

const SECURE_MAIL_QUERY =
  "(ciphertext OR sds. OR filename:securemsg) -subject:re: -subject:fwd: -subject:fw:";

export async function listMailboxMessages(
  accessToken,
  { maxResults = 10, pageToken = null, query = SECURE_MAIL_QUERY } = {},
) {
  const params = new URLSearchParams({
    maxResults: String(maxResults),
    labelIds: "INBOX",
    q: query,
  });
  if (pageToken) params.set("pageToken", pageToken);

  const list = await gmailFetch(
    accessToken,
    `users/me/messages?${params.toString()}`,
  );

  const ids = (list.messages || []).map((m) => m.id);
  const messages = [];

  for (const id of ids) {
    const full = await gmailFetch(
      accessToken,
      `users/me/messages/${encodeURIComponent(id)}?format=full`,
    );
    const headers = full.payload?.headers || [];
    const parts = walkParts(full.payload);
    const bodyText =
      parts.texts.join("\n\n") || stripHtml(parts.htmls.join("\n"));
    const bodyHtml = parts.htmls[0] || "";

    if (
      !isOriginalSecureDocShareMail({
        headers,
        bodyText,
        bodyHtml,
        attachments: parts.attachments,
      })
    ) {
      continue;
    }

    const ownBody = stripQuotedReplyContent(bodyText, bodyHtml);
    const ciphertext =
      extractSdsCiphertext(ownBody) ||
      extractSdsCiphertext(`${bodyText}\n${parts.htmls.join("\n")}`);
    const secureAttachments = parts.attachments.filter((a) =>
      isSecureAttachmentName(a.filename),
    );

    const item = {
      id: full.id,
      threadId: full.threadId,
      snippet: full.snippet || "",
      subject: headerValue(headers, "Subject") || "(no subject)",
      from: headerValue(headers, "From") || "",
      to: headerValue(headers, "To") || "",
      date: headerValue(headers, "Date") || "",
      internalDate: full.internalDate
        ? new Date(Number(full.internalDate)).toISOString()
        : null,
      bodyText,
      bodyHtml,
      ciphertext,
      hasCiphertext: Boolean(ciphertext),
      attachments: parts.attachments,
      secureAttachments,
      canDecrypt: Boolean(ciphertext) || secureAttachments.length > 0,
    };
    messages.push(item);
  }

  console.log(
    "[SecureDocShare] Mailbox page loaded",
    messages.length,
    "nextPageToken:",
    list.nextPageToken || null,
  );

  return {
    messages,
    nextPageToken: list.nextPageToken || null,
  };
}

function stripHtml(html) {
  return String(html || "")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Build a Gmail deep-link for a message/thread (API ids are hex).
 * Avoid /popout?... — Gmail requires internal ver/qid/cvid and crashes without them
 * ("Cannot read properties of null (reading 'js')").
 */
export function gmailPopoutUrl({ messageId, threadId } = {}) {
  const threadHex = String(threadId || "").replace(/^0x/i, "");
  const msgHex = String(messageId || "").replace(/^0x/i, "");

  if (/^[0-9a-f]+$/i.test(threadHex)) {
    const decimal = BigInt(`0x${threadHex}`).toString();
    return `https://mail.google.com/mail/u/0/#all/thread-f:${decimal}`;
  }
  if (/^[0-9a-f]+$/i.test(msgHex)) {
    const decimal = BigInt(`0x${msgHex}`).toString();
    return `https://mail.google.com/mail/u/0/#all/msg-f:${decimal}`;
  }
  return "https://mail.google.com/mail/u/0/#inbox";
}

/**
 * Store decrypted plaintext so the Gmail content script can swap ciphertext.
 */
export async function stashGmailDecryptPayload({
  plaintext,
  ciphertext,
  messageId,
  threadId,
}) {
  const payload = {
    plaintext: String(plaintext || ""),
    ciphertext: ciphertext || null,
    messageId: messageId || null,
    threadId: threadId || null,
    createdAt: Date.now(),
  };
  try {
    await chrome.storage.session.set({ sdsPendingGmailDecrypt: payload });
  } catch {
    await chrome.storage.local.set({ sdsPendingGmailDecrypt: payload });
  }
  return payload;
}

export async function openDecryptedInGmail({
  plaintext,
  ciphertext,
  messageId,
  threadId,
}) {
  await stashGmailDecryptPayload({
    plaintext,
    ciphertext,
    messageId,
    threadId,
  });
  const url = gmailPopoutUrl({ messageId, threadId });
  await chrome.tabs.create({ url });
  return url;
}

export async function downloadGmailAttachment(
  accessToken,
  messageId,
  attachmentId,
) {
  const data = await gmailFetch(
    accessToken,
    `users/me/messages/${encodeURIComponent(
      messageId,
    )}/attachments/${encodeURIComponent(attachmentId)}`,
  );
  return decodeBase64UrlBytes(data.data);
}
