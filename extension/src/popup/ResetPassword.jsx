import React, { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { parseOrThrow, passwordResetRequestSchema } from "../lib/validation";

export default function ResetPassword({ initialEmail = "", onCancel }) {
  const [email, setEmail] = useState(initialEmail);
  const [sent, setSent] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const autoSentRef = useRef(false);

  const sendLink = async (targetEmail) => {
    setError("");
    setStatus("");
    try {
      const values = parseOrThrow(passwordResetRequestSchema, {
        email: targetEmail ?? email,
      });
      setLoading(true);
      const { data } = await api.requestPasswordReset(values.email);
      setEmail(values.email);
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


  return (
    <div className="auth-card app-shell">
      <p className="brand">SecureDocShare</p>
      <h3 className="auth-title">Set / reset password</h3>
      <p className="hint">
        We&apos;ll email you a secure link to set a new password.
      </p>

      {!sent && (
        <>
          <input
            className="field"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={Boolean(initialEmail)}
          />
          <button
            className="btn btn-primary"
            onClick={() => sendLink()}
            disabled={loading}
          >
            {loading ? "Sending..." : "Send reset link"}
          </button>
        </>
      )}

      {sent && (
        <>
          <p className="hint">
            Check <strong>{email}</strong> and open the link to choose a new
            password. The link expires in 30 minutes.
          </p>
          <button
            className="btn btn-secondary"
            onClick={() => sendLink()}
            disabled={loading}
          >
            {loading ? "Sending..." : "Resend link"}
          </button>
        </>
      )}

      <button className="btn btn-ghost" onClick={onCancel}>
        Back
      </button>

      {error && <p className="error-banner">{error}</p>}
    </div>
  );
}
