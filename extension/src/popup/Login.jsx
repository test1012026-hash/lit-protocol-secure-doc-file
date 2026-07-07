import React, { useState } from 'react';
import { api } from '../lib/api';
import { getGoogleOAuthSetup, googleSignIn } from '../lib/googleAuth';
import ResetPassword from './ResetPassword';

export default function Login({ onLogin }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const submit = async () => {
    setError('');
    try {
      const { data } = mode === 'login'
        ? await api.login(email, password)
        : await api.signup(email, password);
      onLogin(data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    }
  };

  const oauthSetup = getGoogleOAuthSetup();

  if (mode === 'reset') {
    return (
      <ResetPassword
        onDone={onLogin}
        onCancel={() => setMode('login')}
      />
    );
  }

  const withGoogle = async () => {
    setError('');
    try {
      const idToken = await googleSignIn();
      const { data } = await api.loginGoogle(idToken);
      onLogin({ ...data, googleIdToken: idToken });
    } catch (err) {
      setError(
        err.message.includes(oauthSetup.redirectUri)
          ? err.message
          : `${err.message} (redirect URI: ${oauthSetup.redirectUri})`
      );
    }
  };

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>{mode === 'login' ? 'Log in' : 'Sign up'}</h3>
      <input
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        style={{ width: '100%', marginBottom: 8 }}
      />
      <input
        placeholder="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        style={{ width: '100%', marginBottom: 8 }}
      />
      <button onClick={submit} style={{ width: '100%', marginBottom: 8 }}>
        {mode === 'login' ? 'Log in' : 'Sign up'}
      </button>
      <button onClick={withGoogle} style={{ width: '100%', marginBottom: 8 }}>
        Continue with Google
      </button>
      {/* <p style={{ fontSize: 11, color: '#666', margin: '0 0 8px' }}>
        Google OAuth redirect URI:
        <br />
        <code style={{ wordBreak: 'break-all' }}>{oauthSetup.redirectUri}</code>
        {!oauthSetup.idMatches && (
          <>
            <br />
            Reload the extension on <code>chrome://extensions</code> (loaded as {oauthSetup.runtimeId}).
          </>
        )}
      </p> */}
      <button
        onClick={() => setMode(mode === 'login' ? 'signup' : 'login')}
        style={{ width: '100%', background: 'none', border: 'none', color: '#357', cursor: 'pointer', marginBottom: 8 }}
      >
        {mode === 'login' ? 'Need an account? Sign up' : 'Already have an account? Log in'}
      </button>
      <button
        onClick={() => setMode('reset')}
        style={{ width: '100%', background: 'none', border: 'none', color: '#357', cursor: 'pointer' }}
      >
        Set / reset password
      </button>
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
    </div>
  );
}
