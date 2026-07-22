chrome.runtime.onInstalled.addListener(() => {
  console.log("SecureDocShare installed");
});

function launchExtensionUi(sender, sendResponse) {
  const url = chrome.runtime.getURL("index.html");

  const finish = () => {
    const err = chrome.runtime.lastError;
    if (err) {
      sendResponse({ ok: false, error: err.message });
      return;
    }
    sendResponse({ ok: true });
  };

  if (sender.tab?.id != null) {
    chrome.tabs.update(sender.tab.id, { url }, finish);
  } else {
    chrome.tabs.create({ url }, finish);
  }
}

function handleLaunch(request, sender, sendResponse) {
  if (request?.action !== "LAUNCH") {
    sendResponse({ ok: false, error: "Unknown action" });
    return false;
  }
  launchExtensionUi(sender, sendResponse);
  return true;
}

chrome.runtime.onMessage.addListener(handleLaunch);
chrome.runtime.onMessageExternal.addListener(handleLaunch);
