import React, { useEffect, useRef, useState } from "react";
import {
  buildContentPayloadBytes,
  buildEncryptedPackage,
  encryptForRecipient,
  getLitActionId,
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
import { provisionRecipientKeyPair } from "../lib/userKeys";
import { sendEncryptedEmailViaGmail } from "../lib/gmailSend";
import RichTextEditor from "./RichTextEditor";
import RecipientEmailInput from "./RecipientEmailInput";

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
    const { data: recipient } = await api.ensureRecipient(
      recipientEmail,
      auth.token,
    );

    let publicKeySpki = recipient.publicKeySpki || null;
    if (DEMO_MODE && !publicKeySpki) {
      const provisioned = await provisionRecipientKeyPair({
        recipientEmail,
        recipientUuid: recipient.recipientUuid,
        token: auth.token,
        getLitActionId,
      });
      publicKeySpki = provisioned.publicKeySpki;
    }

    if (DEMO_MODE && !publicKeySpki) {
      throw new Error(
        `Could not create a public key for ${recipientEmail}. Try again.`,
      );
    }

    const hasMessage = !isEmptyRichText(values.message);
    const hasFile = values.file instanceof File;

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
        { publicKeySpki },
      );
      const messagePackage = await buildEncryptedPackage({
        ciphertext: encryptedMessage.ciphertext,
        iv: encryptedMessage.iv,
        wrappedKey: encryptedMessage.wrappedKey,
        recipientUuidHash: encryptedMessage.recipientUuidHash,
        actionId: encryptedMessage.actionId,
        expectedEmail: recipientEmail,
        filename: "message.json",
        mimeType: "application/json",
        mode: encryptedMessage.mode,
        keyScheme: encryptedMessage.keyScheme,
        kind: "message",
      });
      messageCipherText = messagePackage.cipherText;
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
        { publicKeySpki },
      );
      const packageName =
        values.file.name.replace(/\.[^./\\]+$/, "") || "document";
      encryptedPackage = await buildEncryptedPackage({
        ciphertext: encryptedFile.ciphertext,
        iv: encryptedFile.iv,
        wrappedKey: encryptedFile.wrappedKey,
        recipientUuidHash: encryptedFile.recipientUuidHash,
        actionId: encryptedFile.actionId,
        expectedEmail: recipientEmail,
        filename: `${packageName}.json`,
        mimeType: "application/json",
        mode: encryptedFile.mode,
        keyScheme: encryptedFile.keyScheme,
        kind: "file",
      });
      contentKind = hasMessage ? "bundle" : "file";
    }

    const subjectText =
      values.subject || (hasFile ? values.file.name : "Secure message");

    await api.sendFile(
      {
        recipientEmail,
        recipientUuid: recipient.recipientUuid,
        subject: subjectText,
        message: messageCipherText,
        filename: hasFile ? values.file.name : "message.txt",
        contentKind,
        clientSend: true,
      },
      auth.token,
    );

    await sendEncryptedEmailViaGmail({
      accessToken: gmailAccessToken,
      from,
      to: recipientEmail,
      subject: subjectText,
      message: messageCipherText,
      attachmentName: encryptedPackage?.fileName,
      attachmentBytes: encryptedPackage?.attachmentBytes || null,
      attachmentBase64: encryptedPackage?.attachmentBytes
        ? null
        : encryptedPackage?.base64 || null,
      appUrl,
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
      if (
        recipientEmails.some((email) => normalizeEmail(email) === self)
      ) {
        setStatus("Error: You cannot send to yourself");
        return;
      }

      const values = parseOrThrow(sendFileFormSchema, {
        recipientEmails,
        subject,
        message,
        file,
      });

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
          `Encrypting & sending ${i + 1}/${values.recipientEmails.length}: ${recipientEmail}…`,
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
      const code = err.response?.data?.code || err.code;
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
