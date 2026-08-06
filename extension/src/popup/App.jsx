import React, { useEffect, useState } from "react";
import Login from "./Login";
import SendFile from "./SendFile";
import ReceiveFile from "./ReceiveFile";
import ResetPassword from "./ResetPassword";
import {
  clearAuth,
  getStoredAuth,
  onAuthChanged,
  saveActiveTab,
  saveAuth,
} from "../lib/authStorage";
import { ensureUserKeyPair } from "../lib/userKeys";
import { getLitActionId } from "../lib/lit";
import { api } from "../lib/api";

export default function App() {
  const [auth, setAuth] = useState(null);
  const [tab, setTab] = useState("send");
  const [showSetPassword, setShowSetPassword] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;

    getStoredAuth().then(({ auth: storedAuth, tab: storedTab }) => {
      if (!active) return;
      if (storedAuth) setAuth(storedAuth);
      setTab(storedTab);
      setReady(true);
    });

    const unsubscribe = onAuthChanged((nextAuth) => {
      if (!active) return;
      setAuth(nextAuth);
      if (!nextAuth) setShowSetPassword(false);
    });

    return () => {
      active = false;
      unsubscribe();
    };
  }, []);

  const handleLogin = async (authData) => {
    // Drop ephemeral Google OAuth tokens before any persistence.
    const sanitized = { ...authData };
    delete sanitized.accessToken;
    delete sanitized.scope;
    delete sanitized.googleAccessToken;

    let next = sanitized;
      try {
        await ensureUserKeyPair(sanitized, getLitActionId);
        next = {
          ...sanitized,
          hasPublicKey: true,
        };
      } catch (err) {
        console.error("Key setup failed:", err);
        throw err;
      }
    await saveAuth(next);
    setAuth(next);
    setShowSetPassword(false);
  };

  // Existing sessions: refresh subscription + create keys if missing.
  useEffect(() => {
    if (!auth?.token) return;
    let cancelled = false;
    (async () => {
      try {
        const { data: sub } = await api.getSubscription(auth.token);
        if (!cancelled) {
          setAuth((prev) => {
            if (!prev) return prev;
            const next = { ...prev, ...sub };
            saveAuth(next);
            return next;
          });
        }
      } catch (err) {
        console.error("Subscription refresh failed:", err);
      }
      // Create keys only once; never regenerate on later opens/sends.
      if (auth.hasPublicKey) return;
      try {
        await ensureUserKeyPair(
          { uuid: auth.uuid, token: auth.token, hasPublicKey: false },
          getLitActionId,
        );
        if (!cancelled) {
          setAuth((prev) => {
            if (!prev) return prev;
            const next = { ...prev, hasPublicKey: true };
            saveAuth(next);
            return next;
          });
        }
      } catch (err) {
        console.error("Key setup failed:", err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [auth?.uuid, auth?.token]);

  const handleLogout = async () => {
    try {
      if (auth?.token) {
        await api.logout(auth.token);
      }
    } catch {
      // still clear local session
    }
    await clearAuth();
    setAuth(null);
    setShowSetPassword(false);
  };

  const handleTabChange = (nextTab) => {
    setTab(nextTab);
    saveActiveTab(nextTab);
  };

  if (!ready) {
    return <p className="status-text">Loading...</p>;
  }

  if (!auth) return <Login onLogin={handleLogin} />;

  if (showSetPassword) {
    return (
      <ResetPassword
        initialEmail={auth.email}
        onCancel={() => setShowSetPassword(false)}
      />
    );
  }

  return (
    <div className="panel app-shell">
      <div className="topbar">
        <strong>{auth.email}</strong>
        <button className="btn btn-secondary" style={{ width: "auto", margin: 0 }} onClick={handleLogout}>
          Log out
        </button>
      </div>
      {!auth.hasPassword && (
        <div className="notice">
          You signed in with Google and do not have a password yet.
          <button
            className="btn btn-primary"
            style={{ marginTop: 8, marginBottom: 0 }}
            onClick={() => setShowSetPassword(true)}
          >
            Set password
          </button>
        </div>
      )}
      {auth.subscriptionActive === false && (
        <div className="error-banner" style={{ marginBottom: 12 }}>
          Your free {auth.subscriptionTrialDays || 90}-day trial ended
          {auth.subscriptionExpiresAt
            ? ` on ${new Date(auth.subscriptionExpiresAt).toLocaleDateString()}`
            : ""}
          . Subscribe to continue sending secure mail. Receiving still works.
        </div>
      )}
      {auth.subscriptionActive !== false &&
        typeof auth.subscriptionDaysLeft === "number" &&
        auth.subscriptionDaysLeft <= 14 && (
          <div className="notice" style={{ marginBottom: 12 }}>
            Free trial: {auth.subscriptionDaysLeft} day
            {auth.subscriptionDaysLeft === 1 ? "" : "s"} left
            {auth.subscriptionExpiresAt
              ? ` (ends ${new Date(auth.subscriptionExpiresAt).toLocaleDateString()})`
              : ""}
            .
          </div>
        )}
      <div className="tabs">        <button
          className={`btn btn-tab ${tab === "send" ? "is-active" : ""}`}
          onClick={() => handleTabChange("send")}
          disabled={tab === "send"}
        >
          Send
        </button>
        <button
          className={`btn btn-tab ${tab === "receive" ? "is-active" : ""}`}
          onClick={() => handleTabChange("receive")}
          disabled={tab === "receive"}
        >
          Receive
        </button>
      </div>
      {tab === "send" ? <SendFile auth={auth} /> : <ReceiveFile auth={auth} />}
    </div>
  );
}
