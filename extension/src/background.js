chrome.runtime.onInstalled.addListener(() => {
  console.log('SecureDocShare installed');
});

const COMPOSE_URL = 'https://mail.google.com/mail/u/0/?view=cm&fs=1';
const COMPOSE_WINDOW = { width: 620, height: 720, type: 'popup' };

async function openGmailComposeWindow() {
  const windows = await chrome.windows.getAll({ populate: true, windowTypes: ['popup'] });
  const existing = windows.find((win) =>
    win.tabs?.some((tab) => tab.url?.includes('mail.google.com') && tab.url?.includes('view=cm'))
  );

  if (existing?.id) {
    await chrome.windows.update(existing.id, { focused: true });
    const tab = existing.tabs?.find((t) => t.url?.includes('view=cm'));
    if (tab?.id) chrome.tabs.sendMessage(tab.id, { type: 'START_GMAIL_RECIPIENT_PICK' }).catch(() => {});
    return;
  }

  await chrome.windows.create({
    url: COMPOSE_URL,
    focused: true,
    ...COMPOSE_WINDOW
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'START_GMAIL_RECIPIENT_PICK') {
    chrome.storage.local.set({ pickingRecipient: true }, async () => {
      try {
        await openGmailComposeWindow();
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ ok: false, error: err.message });
      }
    });
    return true;
  }

  if (message.type === 'GMAIL_RECIPIENT_SELECTED') {
    chrome.storage.local.set({
      pendingRecipientEmail: message.email,
      pickingRecipient: false
    }, () => sendResponse({ ok: true }));
    return true;
  }
});
