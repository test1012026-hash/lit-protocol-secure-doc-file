import React, { useEffect, useRef, useState } from "react";
import { buildEncryptedPackage, encryptForRecipient } from "../lib/lit";
import { api } from "../lib/api";
import { DEMO_MODE } from "../lib/config";
import { parseOrThrow, sendFileFormSchema } from "../lib/validation";
import { getStoredAuth } from "../lib/authStorage";
import { normalizeEmail } from "../lib/email";
import { ensureGmailConnected } from "../lib/googleAuth";

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
        setStatus("Error: You cannot send a file to yourself");
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
      const bytes = new Uint8Array(await values.file.arrayBuffer());
      const encrypted = await encryptForRecipient(
        bytes,
        recipient.recipientUuid,
      );
      const encryptedPackage = await buildEncryptedPackage({
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        recipientUuidHash: encrypted.recipientUuidHash,
        expectedEmail: values.recipientEmail,
        filename: values.file.name,
        mimeType: values.file.type || "application/pdf",
        mode: encrypted.mode,
      });

      setStatus("Sending via your Gmail...");
      const { data } = await api.sendFile(
        {
          recipientEmail: values.recipientEmail,
          recipientUuid: recipient.recipientUuid,
          subject: values.subject || values.file.name,
          message: values.message,
          filename: values.file.name,
          encryptedPackageBase64: encryptedPackage.base64,
          encryptedPackageName: encryptedPackage.fileName,
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
          await ensureGmailConnected(auth.token, { ...auth, gmailConnected: false });
          setStatus("Gmail reconnected. Click send again.");
          return;
        } catch (retryErr) {
          setStatus("Error: " + (retryErr.response?.data?.error || retryErr.message));
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
          Demo mode: PDF is AES-encrypted with the recipient UUID.
        </p>
      )}
      <p className="hint">
        Mail sends from your Google account ({auth.email}). Gmail permission is
        asked once, then remembered.
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
      <textarea
        className="field"
        placeholder="Message"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        rows={4}
        style={{ resize: "vertical" }}
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
        <p className={status.startsWith("Error") ? "error-banner" : "status-text status-ok"}>
          {status}
        </p>
      )}
    </div>
  );
}
