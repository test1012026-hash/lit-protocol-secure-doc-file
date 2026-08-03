import axios from 'axios';
import { API_BASE_URL } from './config';

const client = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60_000,
});

function authHeader(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

export const api = {
  signup: (email, password) => client.post('/auth/signup', { email, password }),
  login: (email, password) => client.post('/auth/login', { email, password }),
  loginGoogle: (idToken) => client.post("/auth/login/google", { idToken }),
  exchangeGmailCode: (payload, token) =>
    client.post("/auth/gmail/access-token", payload, authHeader(token)),
  requestPasswordReset: (email) => client.post('/auth/password-reset/request', { email }),
  gmailStatus: (token) => client.get('/auth/gmail/status', authHeader(token)),
  gmailConnect: (token) => client.get('/auth/gmail/connect', authHeader(token)),
  ensureRecipient: (recipientEmail, token) =>
    client.post('/files/ensure-recipient', { recipientEmail }, authHeader(token)),
  provisionRecipientKeys: (payload, token) =>
    client.post('/files/provision-recipient-keys', payload, authHeader(token)),
  sendFile: (payload, token) => client.post('/files/send', payload, authHeader(token)),
  registerKeys: (payload, token) =>
    client.post('/auth/keys', payload, authHeader(token)),
  getMyKeys: (token) => client.get('/auth/keys/me', authHeader(token)),
};
