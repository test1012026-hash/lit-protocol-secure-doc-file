import React, { useEffect, useState } from 'react';
import Login from './Login';
import SendFile from './SendFile';
import Inbox from './Inbox';
import ResetPassword from './ResetPassword';
import { clearAuth, getStoredAuth, onAuthChanged, saveActiveTab, saveAuth } from '../lib/authStorage';

export default function App() {
  const [auth, setAuth] = useState(null);
  const [tab, setTab] = useState('send');
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
    await saveAuth(authData);
    setAuth(authData);
    setShowSetPassword(false);
  };

  const handlePasswordSet = async (authData) => {
    const next = { ...auth, ...authData, hasPassword: true };
    await saveAuth(next);
    setAuth(next);
    setShowSetPassword(false);
  };

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
    return <p style={{ margin: 0, color: '#666' }}>Loading...</p>;
  }

  if (!auth) return <Login onLogin={handleLogin} />;

  if (showSetPassword) {
    return (
      <ResetPassword
        initialEmail={auth.email}
        onDone={handlePasswordSet}
        onCancel={() => setShowSetPassword(false)}
      />
    );
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <strong>{auth.email}</strong>
        <button onClick={handleLogout}>Log out</button>
      </div>
      {!auth.hasPassword && (
        <div style={{ marginBottom: 12, padding: 8, background: '#f5f8ff', borderRadius: 4, fontSize: 12 }}>
          You signed in with Google and do not have a password yet.
          <button
            onClick={() => setShowSetPassword(true)}
            style={{ display: 'block', width: '100%', marginTop: 8 }}
          >
            Set password
          </button>
        </div>
      )}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button onClick={() => handleTabChange('send')} disabled={tab === 'send'} style={{ flex: 1 }}>Send</button>
        <button onClick={() => handleTabChange('inbox')} disabled={tab === 'inbox'} style={{ flex: 1 }}>Inbox</button>
      </div>
      {tab === 'send' ? <SendFile auth={auth} /> : <Inbox auth={auth} />}
    </div>
  );
}
