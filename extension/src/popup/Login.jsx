import React, { useState } from "react";
import { api } from "../lib/api";
import {
  getGoogleOAuthSetup,
  googleSignInWithFullAccess,
} from "../lib/googleAuth";
import { loginSchema, parseOrThrow, signupSchema, signupSendOtpSchema } from "../lib/validation";
import ResetPassword from "./ResetPassword";

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [otpHint, setOtpHint] = useState("");
  const [acceptTerms, setAcceptTerms] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const submit = async () => {
    setError("");
    setLoading(true);
    try {
      if (mode === "signup") {
        if (!otpSent) {
          parseOrThrow(signupSendOtpSchema, {
            email,
            password,
            acceptTerms,
          });
          const { data } = await api.sendSignupOtp(email, true);
          setOtpSent(true);
          setOtp("");
          setOtpHint(
            data?.devOtp
              ? `Dev code: ${data.devOtp} (valid 10 min)`
              : "Code sent. Valid for 10 minutes — a new request replaces the old code.",
          );
          return;
        }
        const values = parseOrThrow(signupSchema, {
          email,
          password,
          acceptTerms,
          otp,
        });
        const { data } = await api.signup(
          values.email,
          values.password,
          true,
          values.otp,
        );
        await onLogin(data);
      } else {
        const values = parseOrThrow(loginSchema, { email, password });
        const { data } = await api.login(values.email, values.password);
        await onLogin(data);
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const resendOtp = async () => {
    setError("");
    setLoading(true);
    try {
      const { data } = await api.sendSignupOtp(email, true);
      setOtpHint(
        data?.devOtp
          ? `Dev code: ${data.devOtp} (valid 10 min)`
          : "New code sent. Valid for 10 minutes — previous code is invalid.",
      );
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
    if (mode === "signup" && !acceptTerms) {
      setError("You must accept the Terms & Conditions to sign up");
      return;
    }
    setGoogleLoading(true);
    try {
      const signIn = async (forceConsent) => {
        const { code, redirectUri } = await googleSignInWithFullAccess({
          forceConsent,
        });
        return api.loginGoogleFull({
          code,
          redirectUri,
          intent: mode === "signup" ? "signup" : "login",
          acceptTerms: mode === "signup" ? true : false,
        });
      };

      let data;
      try {
        ({ data } = await signIn(mode === "signup"));
      } catch (err) {
        if (
          mode === "signup" ||
          err.response?.data?.code !== "GMAIL_CONSENT_REQUIRED"
        ) {
          throw err;
        }
        ({ data } = await signIn(true));
      }

      await onLogin({
        ...data,
        googleIdToken: data.googleIdToken || null,
        gmailConnected: true,
        loginMethod: "google",
        accessToken: undefined,
        scope: undefined,
      });
    } catch (err) {
      const apiError = err.response?.data?.error || err.message;
      setError(
        String(apiError).includes(oauthSetup.redirectUri)
          ? apiError
          : `${apiError}${
              oauthSetup.redirectUri && /redirect/i.test(String(apiError))
                ? ` (redirect URI: ${oauthSetup.redirectUri})`
                : ""
            }`,
      );
    } finally {
      setGoogleLoading(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter") submit();
  };

  const switchMode = (next) => {
    setMode(next);
    setError("");
    setAcceptTerms(false);
    setOtpSent(false);
    setOtp("");
    setOtpHint("");
  };

  return (
    <div className="auth-card app-shell">
      <p className="brand">SecureDocShare</p>
      <p className="brand-sub">
        Encrypt and share documents with identity-locked access.
      </p>
      <h3 className="auth-title">{mode === "login" ? "Log in" : "Sign up"}</h3>
      <input
        className="field"
        placeholder="Email"
        value={email}
        onChange={(e) => {
          setEmail(e.target.value);
          if (mode === "signup") {
            setOtpSent(false);
            setOtp("");
            setOtpHint("");
          }
        }}
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
      {mode === "signup" && (
        <label className="terms-check">
          <input
            type="checkbox"
            checked={acceptTerms}
            onChange={(e) => setAcceptTerms(e.target.checked)}
          />
          <span>
            I agree to the{" "}
            <a
              href="https://securedocs.share/terms"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "var(--text)" }}
            >
              Terms &amp; Conditions
            </a>
          </span>
        </label>
      )}
      {mode === "signup" && otpSent && (
        <>
          <input
            className="field"
            placeholder="4-digit code"
            value={otp}
            onChange={(e) =>
              setOtp(e.target.value.replace(/\D/g, "").slice(0, 4))
            }
            onKeyDown={onKeyDown}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={4}
          />
          {otpHint ? <p className="brand-sub">{otpHint}</p> : null}
          <button
            className="btn btn-ghost"
            type="button"
            onClick={resendOtp}
            disabled={loading || googleLoading}
          >
            Resend code
          </button>
        </>
      )}
      <button
        className="btn btn-primary"
        onClick={submit}
        disabled={
          loading || googleLoading || (mode === "signup" && !acceptTerms)
        }
      >
        {loading
          ? mode === "login"
            ? "Signing in..."
            : otpSent
              ? "Creating account..."
              : "Sending code..."
          : mode === "login"
            ? "Log in"
            : otpSent
              ? "Verify & sign up"
              : "Send verification code"}
      </button>
      <button
        className="btn btn-secondary"
        onClick={() => withGoogle()}
        disabled={
          loading || googleLoading || (mode === "signup" && !acceptTerms)
        }
      >
        {googleLoading ? "Connecting Google..." : "Continue with Google"}
      </button>
      <button
        className="btn btn-ghost"
        onClick={() => switchMode(mode === "login" ? "signup" : "login")}
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
