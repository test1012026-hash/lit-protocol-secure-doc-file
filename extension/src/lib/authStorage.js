const AUTH_KEY = 'auth';
const TAB_KEY = 'activeTab';

export function getStoredAuth() {
  return new Promise((resolve) => {
    chrome.storage.local.get([AUTH_KEY, TAB_KEY], (result) => {
      resolve({
        auth: result[AUTH_KEY] || null,
        tab: result[TAB_KEY] === 'receive' ? 'receive' : 'send'
      });
    });
  });
}

export function saveAuth(auth) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [AUTH_KEY]: auth }, () => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve();
    });
  });
}

export function clearAuth() {
  return new Promise((resolve) => {
    chrome.storage.local.remove([AUTH_KEY], resolve);
  });
}

export function saveActiveTab(tab) {
  chrome.storage.local.set({ [TAB_KEY]: tab });
}

export function onAuthChanged(callback) {
  const listener = (changes, area) => {
    if (area !== 'local' || !changes[AUTH_KEY]) return;
    callback(changes[AUTH_KEY].newValue || null);
  };
  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}
