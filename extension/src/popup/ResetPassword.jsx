import React, { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";

export default function ResetPassword({ initialEmail = "", onCancel }) {
  const [email, setEmail] = useState(initialEmail);
  const [sent, setSent] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const autoSentRef = useRef(false);

  const sendLink = async (targetEmail) => {
    const value = (targetEmail ?? email).trim();
    setError("");
    setStatus("");
    if (!value) {
      setError("Enter your email address.");
      return;
    }
    try {
      setLoading(true);
      const { data } = await api.requestPasswordReset(value);
      setStatus(
        data.message || "A password reset link has been sent to your email.",
      );
      setSent(true);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!initialEmail || autoSentRef.current) return;
    autoSentRef.current = true;
    sendLink(initialEmail);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialEmail]);

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Set / reset password</h3>
      <p style={{ fontSize: 12, color: "#666", marginTop: 0 }}>
        We'll email you a secure link to set a new password.
      </p>

      {!sent && (
        <>
          <input
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={Boolean(initialEmail)}
            style={{ width: "100%", marginBottom: 8 }}
          />
          <button
            onClick={() => sendLink()}
            disabled={loading}
            style={{ width: "100%", marginBottom: 8 }}
          >
            {loading ? "Sending..." : "Send reset link"}
          </button>
        </>
      )}

      {sent && (
        <>
          <p style={{ fontSize: 12, margin: "0 0 8px" }}>
            Check <strong>{email}</strong> and open the link to choose a new
            password. The link expires in 30 minutes.
          </p>
          <button
            onClick={() => sendLink()}
            disabled={loading}
            style={{
              width: "100%",
              marginBottom: 8,
              background: "none",
              border: "1px solid #ccc",
            }}
          >
            {loading ? "Sending..." : "Resend link"}
          </button>
        </>
      )}

      <button
        onClick={onCancel}
        style={{
          width: "100%",
          background: "none",
          border: "none",
          color: "#357",
          cursor: "pointer",
        }}
      >
        Back to login
      </button>

      {status && <p style={{ color: "#357" }}>{status}</p>}
      {error && <p style={{ color: "crimson" }}>{error}</p>}
    </div>
  );
}
