import React, { useEffect, useState } from "react";
import { api } from "../lib/api";
import { decryptFile } from "../lib/lit";
import { googleSignIn } from "../lib/googleAuth";

export default function Inbox({ auth }) {
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState("");

  useEffect(() => {
    api
      .inbox(auth.token)
      .then(({ data }) => setFiles(data))
      .catch(() => {});
  }, [auth.token]);

  const handleDecrypt = async (fileId) => {
    try {
      setStatus("Fetching file...");
      const { data: file } = await api.receiveFile(fileId, auth.token);

      setStatus("Verifying identity with Google...");
      const googleIdToken = auth.googleIdToken || (await googleSignIn());

      setStatus("Decrypting...");
      const decrypted = await decryptFile({
        ciphertext: file.ciphertext,
        dataToEncryptHash: file.dataToEncryptHash,
        litActionCode: file.litActionCode,
        expectedEmail: file.expectedEmail,
        googleIdToken,
      });

      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);
      chrome.downloads.download({
        url,
        filename: file.filename || file.subject,
      });
      setStatus("Downloaded.");
    } catch (err) {
      setStatus("Error: " + (err.response?.data?.error || err.message));
    }
  };

  return (
    <div>
      <h4 style={{ marginTop: 0 }}>Received files</h4>
      {files.length === 0 && <p>No files yet.</p>}
      {files.map((f) => (
        <div
          key={f._id}
          style={{
            marginBottom: 12,
            paddingBottom: 8,
            borderBottom: "1px solid #eee",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 4,
            }}
          >
            <strong style={{ fontSize: 13 }}>{f.subject}</strong>
            <button onClick={() => handleDecrypt(f._id)}>Decrypt</button>
          </div>
          {f.message && (
            <p style={{ fontSize: 12, color: "#555", margin: "0 0 4px" }}>
              {f.message}
            </p>
          )}
          {f.filename && f.filename !== f.subject && (
            <p style={{ fontSize: 11, color: "#888", margin: 0 }}>
              File: {f.filename}
            </p>
          )}
        </div>
      ))}
      {status && <p>{status}</p>}
    </div>
  );
}
