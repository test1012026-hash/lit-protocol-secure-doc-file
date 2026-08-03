import React, { useEffect, useRef, useState } from "react";
import {
  buildContentPayloadBytes,
  buildEncryptedPackage,
  encryptForRecipient,
} from "../lib/lit";
import { api } from "../lib/api";
import { DEMO_MODE } from "../lib/config";
import {
  isEmptyRichText,
  parseOrThrow,
  sendFileFormSchema,
} from "../lib/validation";
import { getStoredAuth } from "../lib/authStorage";
import { normalizeEmail } from "../lib/email";
import { ensureGmailConnected } from "../lib/googleAuth";
import RichTextEditor from "./RichTextEditor";

export default function SendFile({ auth }) {
  const [recipientEmail, setRecipientEmail] = useState("");
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

  const handleSend = async () => {
    try {
      if (normalizeEmail(storedAuth?.email) === normalizeEmail(recipientEmail)) {
        setStatus("Error: You cannot send to yourself");
        return;
      }

      const values = parseOrThrow(sendFileFormSchema, {
        recipientEmail,
        subject,
        message,
        file,
      });

      setLoading(true);
      if (!auth.gmailConnected) {
        setStatus("Allow Gmail access once...");
      }
      await ensureGmailConnected(auth.token, auth);

      setStatus("Creating recipient UUID...");
      const { data: recipient } = await api.ensureRecipient(
        values.recipientEmail,
        auth.token,
      );

      setStatus(
        DEMO_MODE
          ? "Encrypting with recipient UUID..."
          : "Encrypting with UUID + Lit...",
      );

      const hasMessage = !isEmptyRichText(values.message);
      const hasFile = values.file instanceof File;

      // Message → ciphertext for email Message body (paste-decrypt).
      // File → separate encrypted attachment. Never bundle them together.
      let messageCipherText = "";
      let encryptedPackage = null;
      let contentKind = "file";

      if (hasMessage) {
        const messageBytes = await buildContentPayloadBytes({
          message: values.message,
          file: null,
        });
        const encryptedMessage = await encryptForRecipient(
          messageBytes,
          recipient.recipientUuid,
        );
        const messagePackage = await buildEncryptedPackage({
          ciphertext: encryptedMessage.ciphertext,
          iv: encryptedMessage.iv,
          recipientUuidHash: encryptedMessage.recipientUuidHash,
          expectedEmail: values.recipientEmail,
          filename: "message.json",
          mimeType: "application/json",
          mode: encryptedMessage.mode,
          kind: "message",
        });
        messageCipherText = messagePackage.cipherText;
        // Message-only: attach encrypted message so recipient can also upload it.
        if (!hasFile) {
          encryptedPackage = messagePackage;
          contentKind = "message";
        }
      }

      if (hasFile) {
        const fileBytes = await buildContentPayloadBytes({
          message: "",
          file: values.file,
        });
        const encryptedFile = await encryptForRecipient(
          fileBytes,
          recipient.recipientUuid,
        );
        const packageName =
          values.file.name.replace(/\.[^./\\]+$/, "") || "document";
        encryptedPackage = await buildEncryptedPackage({
          ciphertext: encryptedFile.ciphertext,
          iv: encryptedFile.iv,
          recipientUuidHash: encryptedFile.recipientUuidHash,
          expectedEmail: values.recipientEmail,
          filename: `${packageName}.json`,
          mimeType: "application/json",
          mode: encryptedFile.mode,
          kind: "file",
        });
        contentKind = hasMessage ? "bundle" : "file";
      }

      setStatus("Sending via your Gmail...");
      const { data } = await api.sendFile(
        {
          recipientEmail: values.recipientEmail,
          recipientUuid: recipient.recipientUuid,
          subject:
            values.subject ||
            (hasFile ? values.file.name : "Secure message"),
          // Only message ciphertext goes in the email Message field.
          message: messageCipherText,
          filename: hasFile ? values.file.name : "message.txt",
          contentKind,
          encryptedPackageBase64: encryptedPackage.base64,
          encryptedPackageName: encryptedPackage.fileName,
          encryptedPackageText: encryptedPackage.text,
        },
        auth.token,
      );

      setStatus(
        data.emailSent
          ? `Sent from ${data.from || auth.email} to ${values.recipientEmail}.`
          : "Email could not be sent.",
      );
      setRecipientEmail("");
      setSubject("");
      setMessage("");
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";
    } catch (err) {
      const code = err.response?.data?.code;
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
          setStatus(
            "Error: " + (retryErr.response?.data?.error || retryErr.message),
          );
          return;
        }
      }
      setStatus("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {DEMO_MODE && (
        <p className="notice notice-warn">
          Demo mode: message and/or PDF are AES-encrypted with the recipient
          UUID.
        </p>
      )}
      <p className="hint">
        Mail sends from your Google account ({auth.email}). Use the rich text
        editor for formatting; the message is encrypted as ciphertext in the
        email body. PDF becomes an encrypted attachment.
      </p>
      <input
        className="field"
        placeholder="Recipient email"
        value={recipientEmail}
        onChange={(e) => setRecipientEmail(e.target.value)}
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
      <button className="btn btn-primary" onClick={handleSend} disabled={loading}>
        {loading ? "Working..." : "Encrypt and send"}
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
