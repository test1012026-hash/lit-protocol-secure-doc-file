const path = (location.pathname || "").replace(/\/$/, "");
if (path === "/open-extension") {
  chrome.runtime.sendMessage({ action: "LAUNCH" }, () => {
    void chrome.runtime.lastError;
  });
}
