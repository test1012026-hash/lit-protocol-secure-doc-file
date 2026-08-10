import React, { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import {
  isEmptyRichText,
  parseOrThrow,
  sendFileFormSchema,
} from "../lib/validation";
import { getStoredAuth } from "../lib/authStorage";
import { normalizeEmail } from "../lib/email";
import { ensureGmailConnected } from "../lib/googleAuth";
import { sendEncryptedEmailViaGmail } from "../lib/gmailSend";
import { getApiErrorCode, toErrorStatus } from "../utils/utils";
import RichTextEditor from "./RichTextEditor";
import RecipientEmailInput from "./RecipientEmailInput";

async function fileToBase64(file) {
  // FileReader is much faster than manual byte→string→btoa for large PDFs.
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () =>
      reject(reader.error || new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
  const comma = dataUrl.indexOf(",");
  return comma >= 0 ? dataUrl.slice(comma + 1) : dataUrl;
}

export default function SendFile({ auth }) {
  const [recipientEmails, setRecipientEmails] = useState([]);
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [storedAuth, setStoredAuth] = useState(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    getStoredAuth().then(({ auth: stored }) => {
      if (stored) setStoredAuth(stored);
    });
  }, []);

  const sendToOneRecipient = async ({
    recipientEmail,
    values,
    gmailAccessToken,
    from,
    appUrl,
  }) => {
    const hasFile = values.file instanceof File;
    const payload = {
      recipientEmail,
      subject: values.subject || "",
      message: isEmptyRichText(values.message) ? "" : values.message,
    };

    if (hasFile) {
      payload.fileBase64 = await fileToBase64(values.file);
      payload.fileName = values.file.name;
      payload.mimeType = values.file.type || "application/pdf";
    }

    const { data: encrypted } = await api.encryptFile(payload, auth.token);

    await api.sendFile(
      {
        recipientEmail,
        recipientUuid: encrypted.recipientUuid,
        subject: encrypted.subject,
        message: encrypted.messageCipherText || "",
        filename: encrypted.filename,
        contentKind: encrypted.contentKind,
        clientSend: true,
      },
      auth.token,
    );

    const attachment = encrypted.attachment;
    await sendEncryptedEmailViaGmail({
      accessToken: gmailAccessToken,
      from,
      to: recipientEmail,
      subject: encrypted.subject,
      message: encrypted.messageCipherText || "",
      attachmentName: attachment?.fileName,
      attachmentBase64:
        attachment?.attachmentBase64 || attachment?.base64 || null,
      appUrl,
      onProgress: (msg) => {
        if (typeof setStatus === "function") setStatus(msg);
      },
    });
  };

  const handleSend = async () => {
    try {
      if (auth.subscriptionActive === false) {
        setStatus(
          "Error: Your free trial has ended. Subscribe to continue sending mail.",
        );
        return;
      }

      const self = normalizeEmail(storedAuth?.email || auth.email);
      if (recipientEmails.some((email) => normalizeEmail(email) === self)) {
        setStatus("Error: You cannot send to yourself");
        return;
      }

      const values = parseOrThrow(sendFileFormSchema, {
        recipientEmails,
        subject,
        message,
        file,
      });

      if (values.file instanceof File && values.file.size > 18 * 1024 * 1024) {
        setStatus(
          "Error: PDF should be under ~18 MB before encryption so the Gmail message stays under 25 MB.",
        );
        return;
      }

      setLoading(true);
      if (!auth.gmailConnected) {
        setStatus("Allow Gmail access once...");
      }
      await ensureGmailConnected(auth.token, auth);

      const { data: tokenData } = await api.gmailSendToken(auth.token);
      const accessToken = tokenData.accessToken;
      const from = tokenData.from || auth.email;
      const appUrl = tokenData.appUrl;

      const sent = [];
      for (let i = 0; i < values.recipientEmails.length; i++) {
        const recipientEmail = values.recipientEmails[i];
        setStatus(
          `Encrypting ${i + 1}/${values.recipientEmails.length}: ${recipientEmail}…`,
        );
        await sendToOneRecipient({
          recipientEmail,
          values,
          gmailAccessToken: accessToken,
          from,
          appUrl,
        });
        sent.push(recipientEmail);
      }

      setStatus(`Sent from ${from} to ${sent.join(", ")}.`);
      setRecipientEmails([]);
      setSubject("");
      setMessage("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (err) {
      const code = getApiErrorCode(err);
      if (code === "SUBSCRIPTION_EXPIRED") {
        setStatus(
          "Error: " +
            (err.response?.data?.error ||
              "Your free trial has ended. Subscribe to continue sending mail."),
        );
        return;
      }
      if (code === "GMAIL_NOT_CONNECTED") {
        try {
          setStatus("Gmail access expired. Reconnecting...");
          await ensureGmailConnected(auth.token, {
            ...auth,
            gmailConnected: false,
          });
          setStatus("Gmail reconnected. Click send again.");
          return;
        } catch (retryErr) {
          setStatus(toErrorStatus(retryErr));
          return;
        }
      }
      setStatus(toErrorStatus(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">
        Mail sends from your Google account ({auth.email}). Add one or more
        recipients as chips.
      </p>
      <RecipientEmailInput
        auth={auth}
        value={recipientEmails}
        onChange={setRecipientEmails}
        disabled={loading}
        placeholder="Type email, pick suggestion or Add…"
      />
      <input
        className="field"
        placeholder="Subject"
        value={subject}
        onChange={(e) => setSubject(e.target.value)}
      />
      <RichTextEditor
        value={message}
        onChange={setMessage}
        placeholder="Message (encrypted as rich text)"
        disabled={loading}
      />
      <input
        ref={fileInputRef}
        className="field"
        type="file"
        accept="application/pdf,.pdf"
        onChange={(e) => setFile(e.target.files[0] || null)}
      />
      <button
        className="btn btn-primary"
        onClick={handleSend}
        disabled={loading || auth.subscriptionActive === false}
      >
        {loading
          ? "Working..."
          : auth.subscriptionActive === false
            ? "Subscription required"
            : "Encrypt and send"}
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
