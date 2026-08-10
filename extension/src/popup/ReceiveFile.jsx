import React, { useEffect, useRef, useState } from "react";
import DOMPurify from "dompurify";
import { api } from "../lib/api";
import { googleSignIn, getMailboxAccessToken } from "../lib/googleAuth";
import {
  parseOrThrow,
  receiveFileFormSchema,
  receivePasteFormSchema,
} from "../lib/validation";
import {
  downloadGmailAttachment,
  listMailboxMessages,
} from "../lib/gmailMailbox";
import {
  base64ToBytes,
  bytesToBase64,
  escapeHtml,
  looksLikeHtml,
  toErrorStatus,
} from "../utils/utils";

function formatMailDate(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function truncateText(value, maxLen) {
  const text = String(value || "")
    .replace(/\s+/g, " ")
    .trim();
  if (text.length <= maxLen) return text;
  return `${text.slice(0, Math.max(0, maxLen - 1)).trimEnd()}…`;
}

function openMessageTab(text, meta = {}) {
  const isHtml = looksLikeHtml(text);
  const bodyInner = isHtml
    ? DOMPurify.sanitize(String(text), {
        USE_PROFILES: { html: true },
        ALLOWED_TAGS: [
          "p",
          "br",
          "strong",
          "b",
          "em",
          "i",
          "u",
          "s",
          "strike",
          "h1",
          "h2",
          "h3",
          "ul",
          "ol",
          "li",
          "a",
          "span",
          "blockquote",
          "pre",
          "code",
          "div",
        ],
        ALLOWED_ATTR: ["href", "target", "rel", "style", "class"],
      })
    : `<pre class="plain">${escapeHtml(text)}</pre>`;

  const subject = meta.subject || "Decrypted message";
  const from = meta.from || "";
  const to = meta.to || "";
  const dateLabel = formatMailDate(meta.date || meta.internalDate);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(subject)} · SecureDocShare</title>
  <style>
    :root {
      --bg: #f6f8fc;
      --card: #ffffff;
      --text: #202124;
      --muted: #5f6368;
      --line: #e0e3e7;
      --accent: #1a73e8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Google Sans", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      border-bottom: 1px solid var(--line);
      background: var(--card);
      color: var(--muted);
      font-size: 13px;
      justify-content: center;
    }
    .toolbar span { opacity: 0.85; }
    main {
      max-width: 920px;
      margin: 0 auto;
      padding: 20px 24px 48px;
      background: var(--card);
      min-height: calc(100vh - 44px);
      border-left: 1px solid var(--line);
      border-right: 1px solid var(--line);
    }
    h1 {
      margin: 0 0 18px;
      font-size: 22px;
      font-weight: 400;
      line-height: 1.35;
      letter-spacing: -0.01em;
    }
    .meta-row {
      display: grid;
      grid-template-columns: 44px 1fr auto;
      gap: 12px;
      align-items: start;
      margin-bottom: 22px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--line);
    }
    .avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: #1a73e8;
      color: #fff;
      display: grid;
      place-items: center;
      font-weight: 600;
      font-size: 16px;
    }
    .from { font-size: 14px; font-weight: 600; }
    .addrs { margin-top: 2px; font-size: 12px; color: var(--muted); }
    .date { font-size: 12px; color: var(--muted); white-space: nowrap; padding-top: 2px; }
    .body {
      font-size: 14px;
      line-height: 1.6;
      word-break: break-word;
    }
    .body a { color: var(--accent); }
    .body ul, .body ol { padding-left: 1.4em; }
    .plain {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: inherit;
      font-size: 14px;
      line-height: 1.6;
    }
    .badge {
      display: inline-block;
      margin-left: 8px;
      padding: 2px 8px;
      border-radius: 4px;
      background: #e8f0fe;
      color: #1967d2;
      font-size: 11px;
      vertical-align: middle;
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <span>SecureDocShare</span>
    <span>·</span>
    <span>Decrypted mail</span>
  </div>
  <main>
    <h1>${escapeHtml(subject)} <span class="badge">Decrypted</span></h1>
    <div class="meta-row">
      <div class="avatar">${escapeHtml(
        (from || "?").trim().charAt(0).toUpperCase() || "?",
      )}</div>
      <div>
        <div class="from">${escapeHtml(from || "Unknown sender")}</div>
        ${to ? `<div class="addrs">to: ${escapeHtml(to)}</div>` : ""}
      </div>
      <div class="date">${escapeHtml(dateLabel)}</div>
    </div>
    <div class="body">${bodyInner}</div>
  </main>
</body>
</html>`;
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  chrome.tabs.create({ url });
}

async function openDecryptedContent(content, meta = {}) {
  const parts = [];

  if (content.message) {
    openMessageTab(content.message, meta);
    parts.push("decrypted message opened in a new tab");
  }

  if (content.file) {
    const blob = new Blob([content.file.bytes], {
      type: content.file.mimeType || "application/pdf",
    });
    const url = URL.createObjectURL(blob);
    const filename = content.file.filename || "document.pdf";
    const mime = (content.file.mimeType || "").toLowerCase();
    if (mime === "application/pdf" || filename.toLowerCase().endsWith(".pdf")) {
      chrome.tabs.create({ url });
    }
    chrome.downloads.download({ url, filename });
    parts.push("PDF opened and downloaded");
  }

  return parts.length
    ? `Decrypted: ${parts.join("; ")}.`
    : "Decrypted, but no message or file was found.";
}

function contentFromDecryptApi(data) {
  return {
    message: data.message || null,
    file: data.file
      ? {
          filename: data.file.filename || "document.pdf",
          mimeType: data.file.mimeType || "application/pdf",
          bytes: base64ToBytes(data.file.dataBase64),
        }
      : null,
  };
}

export default function ReceiveFile({ auth }) {
  const [receiveMode, setReceiveMode] = useState("file");
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [packageText, setPackageText] = useState("");
  const [statusByMode, setStatusByMode] = useState({
    file: "",
    paste: "",
    mailbox: "",
  });
  const [loading, setLoading] = useState(false);
  const [mailboxLoading, setMailboxLoading] = useState(false);
  const [mailboxLoadingMore, setMailboxLoadingMore] = useState(false);
  const [mailbox, setMailbox] = useState([]);
  const [mailboxNextPageToken, setMailboxNextPageToken] = useState(null);
  const [decryptingId, setDecryptingId] = useState(null);
  const mailboxAccessTokenRef = useRef(null);
  const mailboxLoadingMoreRef = useRef(false);
  const mailboxNextPageTokenRef = useRef(null);
  const mailboxListRef = useRef(null);

  const setTabStatus = (mode, message) => {
    setStatusByMode((prev) => ({ ...prev, [mode]: message || "" }));
  };

  const renderTabStatus = (mode) => {
    const status = statusByMode[mode];
    if (!status) return null;
    return (
      <p
        className={
          status.startsWith("Error") ? "error-banner" : "status-text status-ok"
        }
      >
        {status}
      </p>
    );
  };

  const decryptViaApi = async (apiPayload, meta = {}, statusMode = "file") => {
    setTabStatus(statusMode, "Decrypting on server...");
    const { data } = await api.decryptFile(apiPayload, auth.token);
    const content = contentFromDecryptApi(data);
    return await openDecryptedContent(content, meta);
  };

  const loadMailboxPage = async ({ reset = false } = {}) => {
    if (reset) {
      if (mailboxLoading) return;
    } else if (
      mailboxLoadingMoreRef.current ||
      mailboxLoading ||
      !mailboxNextPageTokenRef.current
    ) {
      return;
    }

    try {
      if (reset) {
        setMailboxLoading(true);
        setTabStatus("mailbox", "Connecting to Gmail...");
        mailboxNextPageTokenRef.current = null;
        setMailboxNextPageToken(null);
      } else {
        mailboxLoadingMoreRef.current = true;
        setMailboxLoadingMore(true);
      }

      let accessToken = mailboxAccessTokenRef.current;
      if (!accessToken || reset) {
        accessToken = await getMailboxAccessToken(auth.token, auth);
        mailboxAccessTokenRef.current = accessToken;
      }

      if (reset) setTabStatus("mailbox", "Loading your inbox...");

      const pageToken = reset ? null : mailboxNextPageTokenRef.current;
      const { messages, nextPageToken } = await listMailboxMessages(
        accessToken,
        {
          maxResults: 10,
          pageToken,
        },
      );

      mailboxNextPageTokenRef.current = nextPageToken;
      setMailboxNextPageToken(nextPageToken);

      setMailbox((prev) => {
        if (reset) return messages;
        const seen = new Set(prev.map((m) => m.id));
        return [...prev, ...messages.filter((m) => !seen.has(m.id))];
      });

      if (reset) {
        setTabStatus(
          "mailbox",
          messages.length
            ? `Loaded ${messages.length} SecureDocShare email${
                messages.length === 1 ? "" : "s"
              }.`
            : "No SecureDocShare emails found.",
        );
      } else {
        setTabStatus(
          "mailbox",
          nextPageToken
            ? `Loaded more (${messages.length} new). Scroll for more.`
            : "All matching SecureDocShare emails loaded.",
        );
      }
    } catch (err) {
      console.error("[SecureDocShare] Mailbox load failed", err);
      setTabStatus("mailbox", toErrorStatus(err));
    } finally {
      setMailboxLoading(false);
      setMailboxLoadingMore(false);
      mailboxLoadingMoreRef.current = false;
    }
  };

  const loadMailbox = () => loadMailboxPage({ reset: true });

  const handleMailboxScroll = (e) => {
    const el = e.currentTarget;
    const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 48;
    if (nearBottom) {
      loadMailboxPage({ reset: false });
    }
  };

  useEffect(() => {
    if (receiveMode !== "mailbox") return;
    if (mailbox.length || mailboxLoading) return;
    loadMailbox();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [receiveMode]);

  // If the list isn't tall enough to scroll, keep loading pages until it is (or inbox ends).
  useEffect(() => {
    if (receiveMode !== "mailbox") return;
    if (mailboxLoading || mailboxLoadingMore) return;
    if (!mailboxNextPageToken) return;
    const el = mailboxListRef.current;
    if (!el) return;
    if (el.scrollHeight <= el.clientHeight + 8) {
      loadMailboxPage({ reset: false });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    mailbox,
    mailboxNextPageToken,
    mailboxLoading,
    mailboxLoadingMore,
    receiveMode,
  ]);

  const handleDecryptMailboxItem = async (item) => {
    try {
      setDecryptingId(item.id);
      setLoading(true);

      if (!auth.uuid) {
        throw new Error(
          "Your account UUID is missing. Log out and log in again.",
        );
      }

      const meta = {
        subject: item.subject,
        from: item.from,
        to: item.to,
        date: item.date,
        internalDate: item.internalDate,
      };

      if (item.ciphertext) {
        setTabStatus(
          "mailbox",
          await decryptViaApi(
            { packageText: item.ciphertext },
            meta,
            "mailbox",
          ),
        );
        return;
      }

      const secure = item.secureAttachments?.[0];
      if (!secure) {
        throw new Error(
          "This email has no SecureDocShare ciphertext or attachment.",
        );
      }

      setTabStatus("mailbox", "Downloading secure attachment...");
      const accessToken = await getMailboxAccessToken(auth.token, auth);
      let bytes = secure.bytes;
      if (!bytes && secure.attachmentId) {
        bytes = await downloadGmailAttachment(
          accessToken,
          item.id,
          secure.attachmentId,
        );
      }
      if (!bytes?.byteLength) {
        throw new Error("Could not download the secure attachment.");
      }
      setTabStatus(
        "mailbox",
        await decryptViaApi(
          { packageBase64: bytesToBase64(bytes) },
          meta,
          "mailbox",
        ),
      );
    } catch (err) {
      console.error("[SecureDocShare] Mailbox decrypt failed", err);
      setTabStatus("mailbox", toErrorStatus(err));
    } finally {
      setDecryptingId(null);
      setLoading(false);
    }
  };

  const handleReceive = async () => {
    const mode = receiveMode === "paste" ? "paste" : "file";
    try {
      setLoading(true);
      if (!auth.uuid) {
        throw new Error(
          "Your account UUID is missing. Log out and log in again.",
        );
      }

      if (mode === "paste") {
        const values = parseOrThrow(receivePasteFormSchema, { packageText });
        setTabStatus(mode, "Sending ciphertext to server...");
        setTabStatus(
          mode,
          await decryptViaApi({ packageText: values.packageText }, {}, mode),
        );
      } else {
        const values = parseOrThrow(receiveFileFormSchema, { encryptedFile });
        setTabStatus(mode, "Uploading encrypted file to server...");
        const bytes = new Uint8Array(await values.encryptedFile.arrayBuffer());
        setTabStatus(
          mode,
          await decryptViaApi(
            { packageBase64: bytesToBase64(bytes) },
            {},
            mode,
          ),
        );
      }
    } catch (err) {
      setTabStatus(mode, toErrorStatus(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">
        Paste the email <b>Message ciphertext</b> (starts with <code>sds.</code>
        ), upload the attachment, or open <b>Your mailbox</b> to decrypt from
        Gmail.
      </p>

      <div className="tabs" style={{ marginBottom: 12 }}>
        <button
          type="button"
          className={`btn btn-tab ${receiveMode === "file" ? "is-active" : ""}`}
          onClick={() => setReceiveMode("file")}
          disabled={loading || receiveMode === "file"}
        >
          Upload file
        </button>
        <button
          type="button"
          className={`btn btn-tab ${
            receiveMode === "paste" ? "is-active" : ""
          }`}
          onClick={() => setReceiveMode("paste")}
          disabled={loading || receiveMode === "paste"}
        >
          Paste ciphertext
        </button>
        <button
          type="button"
          className={`btn btn-tab ${
            receiveMode === "mailbox" ? "is-active" : ""
          }`}
          onClick={() => setReceiveMode("mailbox")}
          disabled={loading || receiveMode === "mailbox"}
        >
          Your mailbox
        </button>
      </div>

      {receiveMode === "mailbox" ? (
        <div className="mailbox">
          <div className="mailbox-toolbar">
            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: "auto", margin: 0 }}
              onClick={loadMailbox}
              disabled={mailboxLoading || loading}
            >
              {mailboxLoading ? "Loading..." : "Refresh"}
            </button>
            <span className="mailbox-count">
              {mailbox.length
                ? `${mailbox.length} secure email${
                    mailbox.length === 1 ? "" : "s"
                  }${mailboxNextPageToken ? " · scroll for more" : ""}`
                : "No emails loaded yet"}
            </span>
          </div>

          {mailboxLoading && !mailbox.length ? (
            <p className="status-text"></p>
          ) : (
            <ul
              className="mailbox-list"
              ref={mailboxListRef}
              onScroll={handleMailboxScroll}
            >
              {mailbox.map((item) => {
                const fromFull = item.from || "(unknown)";
                const subjectFull = item.subject || "(no subject)";
                const snippetFull = item.snippet || "";
                return (
                  <li key={item.id} className="mailbox-item">
                    <div className="mailbox-item-main">
                      <div className="mailbox-from-row">
                        <div className="mailbox-from" title={fromFull}>
                          {truncateText(fromFull, 28)}
                        </div>
                        <button
                          type="button"
                          className="btn btn-primary mailbox-decrypt"
                          disabled={
                            loading ||
                            mailboxLoading ||
                            mailboxLoadingMore ||
                            !item.canDecrypt
                          }
                          onClick={() => handleDecryptMailboxItem(item)}
                        >
                          {decryptingId === item.id ? "Decrypting…" : "Decrypt"}
                        </button>
                      </div>
                      <div className="mailbox-subject" title={subjectFull}>
                        {truncateText(subjectFull, 36)}
                        {item.canDecrypt ? (
                          <span className="mailbox-secure-tag">Secure</span>
                        ) : null}
                      </div>
                      <div
                        className="mailbox-snippet"
                        title={snippetFull}
                        style={{ cursor: "pointer" }}
                      >
                        {truncateText(snippetFull, 50)}
                      </div>
                      <div className="mailbox-date">
                        {formatMailDate(item.internalDate || item.date)}
                      </div>
                    </div>
                  </li>
                );
              })}
              {mailboxLoadingMore ? (
                <li className="mailbox-item mailbox-loading-more">
                  Loading more emails…
                </li>
              ) : null}
              {!mailboxLoadingMore &&
              mailbox.length > 0 &&
              !mailboxNextPageToken ? (
                <li className="mailbox-item mailbox-loading-more">
                  End of matching emails
                </li>
              ) : null}
            </ul>
          )}
          {renderTabStatus("mailbox")}
        </div>
      ) : receiveMode === "paste" ? (
        <div>
          <textarea
            className="field"
            placeholder="Paste Message ciphertext from email (sds.…)"
            value={packageText}
            onChange={(e) => setPackageText(e.target.value)}
            rows={6}
            style={{
              resize: "vertical",
              fontFamily: "ui-monospace, monospace",
              fontSize: 12,
            }}
          />
          <button
            className="btn btn-primary"
            onClick={handleReceive}
            disabled={loading}
          >
            {loading ? "Decrypting..." : "Decrypt and open"}
          </button>
          {renderTabStatus("paste")}
        </div>
      ) : (
        <div>
          <input
            className="field"
            type="file"
            accept=".securepdf,.securemsg,application/json,text/plain"
            onChange={(e) => setEncryptedFile(e.target.files?.[0] || null)}
          />
          <button
            className="btn btn-primary"
            onClick={handleReceive}
            disabled={loading}
          >
            {loading ? "Decrypting..." : "Decrypt and open"}
          </button>
          {renderTabStatus("file")}
        </div>
      )}
    </div>
  );
}
