import React, { useEffect, useRef, useState } from "react";
import { buildEncryptedPackage, encryptForRecipient } from "../lib/lit";
import { api } from "../lib/api";
import { DEMO_MODE } from "../lib/config";
import { parseOrThrow, sendFileFormSchema } from "../lib/validation";
import { getStoredAuth } from "../lib/authStorage";
import { normalizeEmail } from "../lib/email";

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
    getStoredAuth().then(({ auth: storedAuth, tab: storedTab }) => {
      if (storedAuth) setStoredAuth(storedAuth);
    });
  }, []);

  const handleSend = async () => {
    try {
      if (normalizeEmail(storedAuth.email) === normalizeEmail(recipientEmail)) {
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

      setStatus("Sending encrypted PDF...");
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
          ? `Sent. Encrypted PDF emailed to ${values.recipientEmail} (locked to their UUID).`
          : "Email could not be sent because SMTP is not configured on the server.",
      );
      setRecipientEmail("");
      setSubject("");
      setMessage("");
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    } catch (err) {
      setStatus("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {DEMO_MODE && (
        <p className="notice notice-warn">
          Demo mode: PDF is AES-encrypted with the recipient UUID. Without that
          UUID, the file cannot be decrypted.
        </p>
      )}
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
      <button
        className="btn btn-primary"
        onClick={handleSend}
        disabled={loading}
      >
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
