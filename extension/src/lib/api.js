import axios from 'axios';
import { API_BASE_URL } from './config';

const client = axios.create({ baseURL: API_BASE_URL });

function authHeader(token) {
  return { headers: { Authorization: `Bearer ${token}` } };
}

export const api = {
  signup: (email, password) => client.post('/auth/signup', { email, password }),
  login: (email, password) => client.post('/auth/login', { email, password }),
  loginGoogle: (idToken) => client.post('/auth/login/google', { idToken }),
  requestPasswordReset: (email) => client.post('/auth/password-reset/request', { email }),
  sendFile: (payload, token) => client.post('/files/send', payload, authHeader(token)),
  inbox: (token) => client.get('/files/inbox', authHeader(token)),
  receiveFile: (id, token) => client.get(`/files/receive/${id}`, authHeader(token))
};
