import React, { useState } from 'react';
import { encryptForRecipient } from '../lib/lit';
import { api } from '../lib/api';

export default function SendFile({ auth }) {
  const [recipientEmail, setRecipientEmail] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState('');

  const handleSend = async () => {
    if (!file || !recipientEmail) {
      setStatus('Enter a recipient email and pick a file.');
      return;
    }
    try {
      setStatus('Encrypting...');
      const bytes = new Uint8Array(await file.arrayBuffer());
      const { ciphertext, dataToEncryptHash, litActionCode } = await encryptForRecipient(bytes);

      setStatus('Sending...');
      await api.sendFile(
        {
          recipientEmail,
          subject: subject.trim() || file.name,
          message: message.trim(),
          filename: file.name,
          ciphertext,
          dataToEncryptHash,
          litActionCode
        },
        auth.token
      );

      setStatus('Sent.');
      setRecipientEmail('');
      setSubject('');
      setMessage('');
      setFile(null);
    } catch (err) {
      setStatus('Error: ' + (err.response?.data?.error || err.message));
    }
  };

  return (
    <div>
      <input
        placeholder="Recipient email"
        value={recipientEmail}
        onChange={(e) => setRecipientEmail(e.target.value)}
        style={{ width: '100%', marginBottom: 8 }}
      />
      <input
        placeholder="Subject"
        value={subject}
        onChange={(e) => setSubject(e.target.value)}
        style={{ width: '100%', marginBottom: 8 }}
      />
      <textarea
        placeholder="Message"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        rows={4}
        style={{ width: '100%', marginBottom: 8, resize: 'vertical', boxSizing: 'border-box' }}
      />
      <input
        type="file"
        onChange={(e) => setFile(e.target.files[0] || null)}
        style={{ width: '100%', marginBottom: 8 }}
      />
      <button onClick={handleSend} style={{ width: '100%' }}>Encrypt and send</button>
      {status && <p>{status}</p>}
    </div>
  );
}
