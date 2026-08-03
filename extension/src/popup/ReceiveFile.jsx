import React, { useState } from "react";
import DOMPurify from "dompurify";
import {
  decryptForRecipient,
  parseDecryptedContent,
  parseEncryptedPackage,
} from "../lib/lit";
import { googleSignIn } from "../lib/googleAuth";
import { DEMO_MODE } from "../lib/config";
import {
  parseOrThrow,
  receiveFileFormSchema,
  receivePasteFormSchema,
} from "../lib/validation";

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function looksLikeHtml(text) {
  return /<\/?[a-z][\s\S]*>/i.test(String(text || ""));
}

function openMessageTab(text) {
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
        ],
        ALLOWED_ATTR: ["href", "target", "rel", "style", "class"],
      })
    : `<pre>${escapeHtml(text)}</pre>`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Decrypted message · SecureDocShare</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Georgia, "Times New Roman", serif;
      background: linear-gradient(160deg, #0f1c24, #17303b 55%, #1f3d4a);
      color: #1c2330;
    }
    main {
      max-width: 720px;
      margin: 40px auto;
      padding: 28px 26px;
      background: #fff;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(30, 50, 90, 0.12);
    }
    h1 { font-size: 22px; margin: 0 0 8px; font-family: system-ui, sans-serif; }
    .meta { margin: 0 0 20px; color: #667085; font-size: 13px; font-family: system-ui, sans-serif; }
    .ql-content {
      font-size: 16px;
      line-height: 1.55;
      word-break: break-word;
    }
    .ql-content a { color: #1f9a89; }
    .ql-content ul, .ql-content ol { padding-left: 1.4em; }
    .ql-content h1, .ql-content h2, .ql-content h3 {
      font-family: system-ui, sans-serif;
      margin: 0.6em 0 0.35em;
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 16px;
      line-height: 1.55;
      font-family: Georgia, "Times New Roman", serif;
    }
  </style>
</head>
<body>
  <main>
    <h1>Decrypted message</h1>
    <p class="meta">Unlocked with your RSA private key (passphrase = UUID + Lit action id).</p>
    <div class="ql-content">${bodyInner}</div>
  </main>
</body>
</html>`;
  const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
  chrome.tabs.create({ url });
}
function openDecryptedContent(content) {
  const parts = [];

  // Message: open only in a new tab (no download / no other UI).
  if (content.message) {
    openMessageTab(content.message);
    parts.push("message opened in a new tab");
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

export default function ReceiveFile({ auth }) {
  const [receiveMode, setReceiveMode] = useState("file"); // file | paste
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [packageText, setPackageText] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const handleReceive = async () => {
    try {
      setLoading(true);
      if (!auth.uuid) {
        throw new Error(
          "Your account UUID is missing. Log out and log in again.",
        );
      }

      let rawText;
      if (receiveMode === "paste") {
        const values = parseOrThrow(receivePasteFormSchema, { packageText });
        rawText = values.packageText;
        setStatus("Reading pasted encrypted package...");
      } else {
        const values = parseOrThrow(receiveFileFormSchema, { encryptedFile });
        setStatus("Reading encrypted file...");
        rawText = await values.encryptedFile.text();
      }

      const encryptedPackage = parseEncryptedPackage(rawText);

      let googleIdToken = auth.googleIdToken || null;
      if (!DEMO_MODE && encryptedPackage.mode === "lit") {
        setStatus("Verifying identity with Google...");
        googleIdToken = googleIdToken || (await googleSignIn());
      }

      setStatus("Unlocking private key + decrypting...");
      const decrypted = await decryptForRecipient({
        encryptedPackage,
        recipientUuid: auth.uuid,
        googleIdToken,
        authToken: auth.token,
      });

      const content = parseDecryptedContent(decrypted, encryptedPackage);
      setStatus(openDecryptedContent(content));
    } catch (err) {
      setStatus("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">
        Paste the email <b>Message ciphertext</b> (starts with <code>sds.</code>
        ) to decrypt the message, or upload the attachment to decrypt the file.
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
          className={`btn btn-tab ${receiveMode === "paste" ? "is-active" : ""}`}
          onClick={() => setReceiveMode("paste")}
          disabled={loading || receiveMode === "paste"}
        >
          Paste ciphertext
        </button>
      </div>

      {receiveMode === "paste" ? (
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
      ) : (
        <input
          className="field"
          type="file"
          accept=".securepdf,.securemsg,application/json,text/plain"
          onChange={(e) => setEncryptedFile(e.target.files?.[0] || null)}
        />
      )}

      <button
        className="btn btn-primary"
        onClick={handleReceive}
        disabled={loading}
      >
        {loading ? "Decrypting..." : "Decrypt and open"}
      </button>
      {status && (
        <p
          className={
            status.startsWith("Error")
              ? "error-banner"
              : "status-text status-ok"
          }
        >
          {status}
        </p>
      )}
    </div>
  );
}
