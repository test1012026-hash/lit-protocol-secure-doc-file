const PICK_FLAG = 'pickingRecipient';
const PENDING_EMAIL = 'pendingRecipientEmail';
const COMPOSE_URL = 'https://mail.google.com/mail/u/0/?view=cm&fs=1';

export function startGmailRecipientPick() {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type: 'START_GMAIL_RECIPIENT_PICK' }, (response) => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve(response);
    });
  });
}

export function onPendingRecipient(callback) {
  chrome.storage.local.get([PENDING_EMAIL], (result) => {
    if (result[PENDING_EMAIL]) {
      callback(result[PENDING_EMAIL]);
      chrome.storage.local.remove([PENDING_EMAIL]);
    }
  });

  const listener = (changes, area) => {
    if (area !== 'local' || !changes[PENDING_EMAIL]?.newValue) return;
    callback(changes[PENDING_EMAIL].newValue);
    chrome.storage.local.remove([PENDING_EMAIL]);
  };

  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}

export { PICK_FLAG, PENDING_EMAIL, COMPOSE_URL };
