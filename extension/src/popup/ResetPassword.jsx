import React, { useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';

const STEPS = {
  EMAIL: 'email',
  OTP: 'otp',
  PASSWORD: 'password',
};

export default function ResetPassword({ initialEmail = '', onDone, onCancel }) {
  const [step, setStep] = useState(initialEmail ? STEPS.OTP : STEPS.EMAIL);
  const [email, setEmail] = useState(initialEmail);
  const autoSentRef = useRef(false);
  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const sendOtp = async () => {
    setError('');
    setStatus('');
    if (!email.trim()) {
      setError('Enter your email address.');
      return;
    }
    try {
      setLoading(true);
      const { data } = await api.requestPasswordReset(email.trim());
      setStatus(data.message || 'Verification code sent.');
      setStep(STEPS.OTP);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!initialEmail || autoSentRef.current) return;
    autoSentRef.current = true;

    (async () => {
      setError('');
      setStatus('');
      try {
        setLoading(true);
        const { data } = await api.requestPasswordReset(initialEmail.trim());
        setStatus(data.message || 'Verification code sent.');
        setStep(STEPS.OTP);
      } catch (err) {
        setError(err.response?.data?.error || err.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [initialEmail]);

  const verifyOtp = async () => {
    setError('');
    setStatus('');
    if (!otp.trim()) {
      setError('Enter the verification code from your email.');
      return;
    }
    try {
      setLoading(true);
      const { data } = await api.verifyPasswordResetOtp(email.trim(), otp.trim());
      setResetToken(data.resetToken);
      setStatus('Code verified. Choose a new password.');
      setStep(STEPS.PASSWORD);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  const setNewPassword = async () => {
    setError('');
    setStatus('');
    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    try {
      setLoading(true);
      const { data } = await api.completePasswordReset(email.trim(), resetToken, password);
      setStatus('Password saved.');
      onDone?.(data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Set / reset password</h3>
      <p style={{ fontSize: 12, color: '#666', marginTop: 0 }}>
        Use this if you signed in with Google and want to add a password.
      </p>

      {step === STEPS.EMAIL && (
        <>
          <input
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={Boolean(initialEmail)}
            style={{ width: '100%', marginBottom: 8 }}
          />
          <button onClick={sendOtp} disabled={loading} style={{ width: '100%', marginBottom: 8 }}>
            {loading ? 'Sending...' : 'Send verification code'}
          </button>
        </>
      )}

      {step === STEPS.OTP && (
        <>
          <p style={{ fontSize: 12, margin: '0 0 8px' }}>Code sent to <strong>{email}</strong></p>
          <input
            placeholder="6-digit code"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            style={{ width: '100%', marginBottom: 8 }}
          />
          <button onClick={verifyOtp} disabled={loading} style={{ width: '100%', marginBottom: 8 }}>
            {loading ? 'Verifying...' : 'Verify code'}
          </button>
          <button
            onClick={sendOtp}
            disabled={loading}
            style={{ width: '100%', marginBottom: 8, background: 'none', border: '1px solid #ccc' }}
          >
            Resend code
          </button>
        </>
      )}

      {step === STEPS.PASSWORD && (
        <>
          <input
            placeholder="New password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: '100%', marginBottom: 8 }}
          />
          <input
            placeholder="Confirm password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            style={{ width: '100%', marginBottom: 8 }}
          />
          <button onClick={setNewPassword} disabled={loading} style={{ width: '100%', marginBottom: 8 }}>
            {loading ? 'Saving...' : 'Save password'}
          </button>
        </>
      )}

      <button
        onClick={onCancel}
        style={{ width: '100%', background: 'none', border: 'none', color: '#357', cursor: 'pointer' }}
      >
        Back to login
      </button>

      {status && <p style={{ color: '#357' }}>{status}</p>}
      {error && <p style={{ color: 'crimson' }}>{error}</p>}
    </div>
  );
}
