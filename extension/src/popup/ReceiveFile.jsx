import React, { useState } from "react";
import { decryptForRecipient, parseEncryptedPackage } from "../lib/lit";
import { googleSignIn } from "../lib/googleAuth";
import { DEMO_MODE } from "../lib/config";
import { parseOrThrow, receiveFileFormSchema } from "../lib/validation";

export default function ReceiveFile({ auth }) {
  const [encryptedFile, setEncryptedFile] = useState(null);
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const handleReceive = async () => {
    try {
      const values = parseOrThrow(receiveFileFormSchema, { encryptedFile });

      setLoading(true);
      if (!auth.uuid) {
        throw new Error(
          "Your account UUID is missing. Log out and log in again.",
        );
      }

      setStatus("Reading encrypted file...");
      const packageText = await values.encryptedFile.text();
      const encryptedPackage = parseEncryptedPackage(packageText);

      let googleIdToken = auth.googleIdToken || null;
      if (!DEMO_MODE && encryptedPackage.mode === "lit") {
        setStatus("Verifying identity with Google...");
        googleIdToken = googleIdToken || (await googleSignIn());
      }

      setStatus("Decrypting with your UUID...");
      const decrypted = await decryptForRecipient({
        encryptedPackage,
        recipientUuid: auth.uuid,
        googleIdToken,
      });

      const blob = new Blob([decrypted], {
        type: encryptedPackage.mimeType || "application/pdf",
      });
      const url = URL.createObjectURL(blob);
      const filename = encryptedPackage.filename || "document.pdf";

      if (
        (encryptedPackage.mimeType || "").toLowerCase() === "application/pdf" ||
        filename.toLowerCase().endsWith(".pdf")
      ) {
        chrome.tabs.create({ url });
      }

      chrome.downloads.download({
        url,
        filename,
      });
      setStatus("PDF decrypted, opened, and downloaded.");
    } catch (err) {
      setStatus("Error: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <p className="hint">
        Upload the <code>.securepdf</code> attachment. Decryption uses your
        account UUID — without the matching UUID the PDF cannot be opened.
      </p>
      <p className="hint">
        Do not open the emailed file directly. Decrypt here after logging into
        the recipient account — access is locked to that account&apos;s UUID,
        not the email string (aliases are fine).
      </p>
      <input
        className="field"
        type="file"
        accept=".securepdf,application/json"
        onChange={(e) => setEncryptedFile(e.target.files?.[0] || null)}
      />
      <button
        className="btn btn-primary"
        onClick={handleReceive}
        disabled={loading}
      >
        {loading ? "Decrypting..." : "Decrypt and open PDF"}
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
