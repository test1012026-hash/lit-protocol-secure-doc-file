const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');
const { sendOtpEmail } = require('../lib/mail');

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const OTP_TTL_MS = 10 * 60 * 1000;
const RESET_TOKEN_TTL = '15m';
const MAX_OTP_ATTEMPTS = 5;

function issueToken(user) {
  return jwt.sign({ uuid: user.uuid, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function userPayload(user) {
  return {
    token: issueToken(user),
    uuid: user.uuid,
    email: user.email,
    hasPassword: Boolean(user.passwordHash)
  };
}

function normalizeEmail(email) {
  return email?.toLowerCase().trim();
}

function generateOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

function issueResetToken(email) {
  return jwt.sign({ email, purpose: 'password-reset' }, process.env.JWT_SECRET, { expiresIn: RESET_TOKEN_TTL });
}

function verifyResetToken(token, email) {
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  if (payload.purpose !== 'password-reset' || payload.email !== email) {
    throw new Error('Invalid reset token');
  }
  return payload;
}

router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    let user = await User.findOne({ email: email.toLowerCase() });
    if (user?.claimed) return res.status(409).json({ error: 'An account with this email already exists' });

    const passwordHash = await bcrypt.hash(password, 12);
    if (user) {
      user.passwordHash = passwordHash;
      user.claimed = true;
    } else {
      user = new User({ email: email.toLowerCase(), passwordHash, claimed: true });
    }
    await user.save();

    res.json(userPayload(user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email?.toLowerCase(), claimed: true });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    res.json(userPayload(user));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/login/google', async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'Missing idToken' });

    const ticket = await googleClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email.toLowerCase();

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, googleId: payload.sub, claimed: true });
    } else {
      user.googleId = payload.sub;
      user.claimed = true;
    }
    await user.save();

    res.json(userPayload(user));
  } catch (err) {
    res.status(401).json({ error: 'Google verification failed: ' + err.message });
  }
});

router.post('/password-reset/request', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await User.findOne({ email, claimed: true });
    if (!user) return res.status(404).json({ error: 'No account found for this email' });

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + OTP_TTL_MS);

    await PasswordReset.findOneAndUpdate(
      { email },
      { email, otpHash, expiresAt, attempts: 0 },
      { upsert: true, new: true }
    );

    await sendOtpEmail(email, otp);
    res.json({ ok: true, message: 'Verification code sent to your email' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/password-reset/verify', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || '').trim();
    if (!email || !otp) return res.status(400).json({ error: 'Email and verification code are required' });

    const record = await PasswordReset.findOne({ email });
    if (!record) return res.status(400).json({ error: 'Request a new verification code first' });
    if (record.expiresAt < new Date()) {
      await PasswordReset.deleteOne({ email });
      return res.status(400).json({ error: 'Verification code expired. Request a new one.' });
    }
    if (record.attempts >= MAX_OTP_ATTEMPTS) {
      await PasswordReset.deleteOne({ email });
      return res.status(429).json({ error: 'Too many attempts. Request a new verification code.' });
    }

    const valid = await bcrypt.compare(otp, record.otpHash);
    if (!valid) {
      record.attempts += 1;
      await record.save();
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    await PasswordReset.deleteOne({ email });
    res.json({ resetToken: issueResetToken(email) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/password-reset/complete', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const { resetToken, password } = req.body;
    if (!email || !resetToken || !password) {
      return res.status(400).json({ error: 'Email, reset token, and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    verifyResetToken(resetToken, email);

    const user = await User.findOne({ email, claimed: true });
    if (!user) return res.status(404).json({ error: 'No account found for this email' });

    user.passwordHash = await bcrypt.hash(password, 12);
    await user.save();

    res.json(userPayload(user));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;
