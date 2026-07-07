const BANNER_ID = 'sds-gmail-recipient-banner';

function extractEmailFromCompose() {
  const selectors = [
    'input[name="to"]',
    'textarea[name="to"]',
    'input[aria-label="To recipients"]',
    '[aria-label="To recipients"] input',
    '[data-hovercard-id*="@"]'
  ];

  for (const selector of selectors) {
    for (const node of document.querySelectorAll(selector)) {
      const value = node.value || node.getAttribute('data-hovercard-id') || node.textContent || '';
      const match = value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
      if (match) return match[0].toLowerCase();
    }
  }

  const bodyText = document.body?.innerText || '';
  const match = bodyText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0].toLowerCase() : '';
}

function removeBanner() {
  document.getElementById(BANNER_ID)?.remove();
}

function renderBanner(email) {
  removeBanner();

  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  banner.style.cssText = [
    'position:fixed',
    'top:16px',
    'right:16px',
    'z-index:999999',
    'background:#1a73e8',
    'color:#fff',
    'padding:12px 14px',
    'border-radius:8px',
    'box-shadow:0 4px 16px rgba(0,0,0,.2)',
    'font:13px/1.4 system-ui,sans-serif',
    'max-width:320px'
  ].join(';');

  const title = document.createElement('div');
  title.textContent = 'SecureDocShare';
  title.style.fontWeight = '600';
  title.style.marginBottom = '6px';

  const text = document.createElement('div');
  text.textContent = email
    ? `Use ${email} as the secure file recipient?`
    : 'Add a recipient in the To field, then click Use recipient.';

  const button = document.createElement('button');
  button.textContent = email ? 'Use recipient' : 'Waiting for To field...';
  button.disabled = !email;
  button.style.cssText = [
    'margin-top:10px',
    'width:100%',
    'border:none',
    'border-radius:4px',
    'padding:8px 10px',
    'background:#fff',
    'color:#1a73e8',
    'font-weight:600',
    'cursor:pointer'
  ].join(';');

  button.addEventListener('click', () => {
    if (!email) return;
    chrome.runtime.sendMessage({ type: 'GMAIL_RECIPIENT_SELECTED', email }, () => {
      removeBanner();
      chrome.storage.local.set({ pickingRecipient: false });
    });
  });

  banner.append(title, text, button);
  document.body.appendChild(banner);
}

function refreshBanner() {
  chrome.storage.local.get(['pickingRecipient'], (result) => {
    if (!result.pickingRecipient) {
      removeBanner();
      return;
    }
    renderBanner(extractEmailFromCompose());
  });
}

function watchCompose() {
  refreshBanner();
  document.addEventListener('input', refreshBanner, true);
  document.addEventListener('click', refreshBanner, true);
  setInterval(refreshBanner, 1500);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local' || !changes.pickingRecipient) return;
  if (changes.pickingRecipient.newValue) refreshBanner();
  else removeBanner();
});

chrome.storage.local.get(['pickingRecipient'], (result) => {
  if (result.pickingRecipient) watchCompose();
});

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'START_GMAIL_RECIPIENT_PICK') watchCompose();
});
