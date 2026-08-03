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
import { DEMO_MODE } from "../lib/config";
import { getLitActionId } from "../lib/lit";

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
    let next = authData;
    if (DEMO_MODE) {
      try {
        await ensureUserKeyPair(authData, getLitActionId);
        next = {
          ...authData,
          hasPublicKey: true,
        };
      } catch (err) {
        console.error("Key setup failed:", err);
        throw err;
      }
    }
    await saveAuth(next);
    setAuth(next);
    setShowSetPassword(false);
  };

  // Existing sessions: create/upload keys once if missing.
  useEffect(() => {
    if (!auth?.token || !DEMO_MODE) return;
    let cancelled = false;
    (async () => {
      try {
        await ensureUserKeyPair(auth, getLitActionId);
        if (!cancelled && !auth.hasPublicKey) {
          const next = {
            ...auth,
            hasPublicKey: true,
          };
          await saveAuth(next);
          setAuth(next);
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
      <div className="tabs">
        <button
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
