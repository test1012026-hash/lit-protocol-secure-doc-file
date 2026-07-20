import React, { useState } from "react";
import { api } from "../lib/api";
import { getGoogleOAuthSetup, googleSignIn } from "../lib/googleAuth";
import { loginSchema, parseOrThrow, signupSchema } from "../lib/validation";
import ResetPassword from "./ResetPassword";

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const submit = async () => {
    setError("");
    setLoading(true);
    try {
      const schema = mode === "login" ? loginSchema : signupSchema;
      const values = parseOrThrow(schema, { email, password });
      const { data } =
        mode === "login"
          ? await api.login(values.email, values.password)
          : await api.signup(values.email, values.password);
      onLogin(data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const oauthSetup = getGoogleOAuthSetup();

  if (mode === "reset") {
    return <ResetPassword onCancel={() => setMode("login")} />;
  }

  const withGoogle = async () => {
    setError("");
    setGoogleLoading(true);
    try {
      const idToken = await googleSignIn();
      const { data } = await api.loginGoogle(idToken);
      onLogin({ ...data, googleIdToken: idToken });
    } catch (err) {
      setError(
        err.message.includes(oauthSetup.redirectUri)
          ? err.message
          : `${err.message} (redirect URI: ${oauthSetup.redirectUri})`,
      );
    } finally {
      setGoogleLoading(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter") submit();
  };

  return (
    <div className="auth-card app-shell">
      <p className="brand">SecureDocShare</p>
      <p className="brand-sub">
        Encrypt and share documents with identity-locked access.
      </p>
      <h3 className="auth-title">
        {mode === "login" ? "Log in" : "Sign up"}
      </h3>
      <input
        className="field"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        onKeyDown={onKeyDown}
        autoComplete="email"
      />
      <input
        className="field"
        placeholder="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        onKeyDown={onKeyDown}
        autoComplete={mode === "login" ? "current-password" : "new-password"}
      />
      <button
        className="btn btn-primary"
        onClick={submit}
        disabled={loading || googleLoading}
      >
        {loading
          ? mode === "login"
            ? "Signing in..."
            : "Creating account..."
          : mode === "login"
            ? "Log in"
            : "Sign up"}
      </button>
      <button
        className="btn btn-secondary"
        onClick={withGoogle}
        disabled={loading || googleLoading}
      >
        {googleLoading ? "Connecting Google..." : "Continue with Google"}
      </button>
      <button
        className="btn btn-ghost"
        onClick={() => setMode(mode === "login" ? "signup" : "login")}
      >
        {mode === "login"
          ? "Need an account? Sign up"
          : "Already have an account? Log in"}
      </button>
      <button className="btn btn-ghost" onClick={() => setMode("reset")}>
        Set / reset password
      </button>
      {error && <p className="error-banner">{error}</p>}
    </div>
  );
}
