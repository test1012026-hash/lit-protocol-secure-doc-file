/**
 * Injected on mail.google.com — replaces sds.* ciphertext with decrypted plaintext
 * after the extension opens the Gmail popout/thread.
 */
(() => {
  const STORAGE_KEY = "sdsPendingGmailDecrypt";
  let lastAppliedAt = 0;

  function looksLikeHtml(text) {
    return /<\/?[a-z][\s\S]*>/i.test(String(text || ""));
  }

  function sanitizeBasicHtml(html) {
    const allowed = new Set([
      "P",
      "BR",
      "STRONG",
      "B",
      "EM",
      "I",
      "U",
      "S",
      "UL",
      "OL",
      "LI",
      "A",
      "SPAN",
      "DIV",
      "BLOCKQUOTE",
      "PRE",
      "CODE",
      "H1",
      "H2",
      "H3",
    ]);
    const tpl = document.createElement("template");
    tpl.innerHTML = String(html || "");
    const walk = (node) => {
      const children = [...node.childNodes];
      for (const child of children) {
        if (child.nodeType === Node.ELEMENT_NODE) {
          if (!allowed.has(child.tagName)) {
            child.replaceWith(...child.childNodes);
            continue;
          }
          for (const attr of [...child.attributes]) {
            const name = attr.name.toLowerCase();
            if (name.startsWith("on") || name === "style") {
              child.removeAttribute(attr.name);
            } else if (name === "href") {
              const href = String(child.getAttribute("href") || "");
              if (!/^(https?:|mailto:)/i.test(href)) {
                child.removeAttribute("href");
              }
            } else if (name !== "target" && name !== "rel") {
              child.removeAttribute(attr.name);
            }
          }
          walk(child);
        }
      }
    };
    walk(tpl.content);
    return tpl.innerHTML;
  }

  function buildReplacementNode(plaintext) {
    const wrap = document.createElement("div");
    wrap.className = "sds-decrypted-message";
    wrap.setAttribute("data-sds-decrypted", "1");
    wrap.style.cssText =
      "white-space:pre-wrap;word-break:break-word;color:#202124;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;";

    if (looksLikeHtml(plaintext)) {
      wrap.innerHTML = sanitizeBasicHtml(plaintext);
      wrap.style.whiteSpace = "normal";
    } else {
      wrap.textContent = String(plaintext || "");
    }

    const badge = document.createElement("div");
    badge.textContent = "Decrypted by SecureDocShare";
    badge.style.cssText =
      "margin-bottom:8px;font-size:11px;color:#1967d2;font-weight:600;";
    wrap.prepend(badge);
    return wrap;
  }

  function elementContainsSds(el) {
    const t = el?.textContent || "";
    return /sds\./i.test(t);
  }

  function findCiphertextHosts() {
    const roots = [document.body];
    const hosts = [];
    for (const root of roots) {
      if (!root) continue;
      const all = root.querySelectorAll("div, span, pre, p, font, td");
      for (const el of all) {
        if (!elementContainsSds(el)) continue;
        // Prefer deepest elements that still contain sds.
        const childHas = [...el.children].some((c) => elementContainsSds(c));
        if (childHas) continue;
        hosts.push(el);
      }
    }
    return hosts;
  }

  function replaceInHosts(plaintext) {
    const hosts = findCiphertextHosts();
    if (!hosts.length) return false;

    let replaced = 0;
    for (const host of hosts) {
      if (host.closest("[data-sds-decrypted='1']")) continue;
      const replacement = buildReplacementNode(plaintext);
      // If parent is a small wrapper around the green cipher span, replace host.
      host.replaceWith(replacement);
      replaced += 1;
    }

    // Also hide common instruction lines under the cipher.
    const instructions = document.querySelectorAll("div, p, span, li");
    for (const el of instructions) {
      const t = (el.textContent || "").trim();
      if (
        /copy and paste the message ciphertext/i.test(t) ||
        /the encrypted file is attached separately/i.test(t)
      ) {
        if (![...el.querySelectorAll("*")].length || el.children.length === 0) {
          el.style.display = "none";
        }
      }
    }

    return replaced > 0;
  }

  async function tryApply() {
    const data = await chrome.storage.session
      .get(STORAGE_KEY)
      .catch(() => chrome.storage.local.get(STORAGE_KEY));
    const payload = data?.[STORAGE_KEY];
    if (!payload?.plaintext) return;
    if (payload.createdAt && Date.now() - payload.createdAt > 10 * 60 * 1000) {
      return;
    }
    // Avoid thrashing the same payload every mutation.
    if (payload.createdAt && payload.createdAt === lastAppliedAt) {
      if (document.querySelector("[data-sds-decrypted='1']")) return;
    }

    const ok = replaceInHosts(payload.plaintext);
    if (ok) {
      lastAppliedAt = payload.createdAt || Date.now();
      console.log("[SecureDocShare] Replaced ciphertext in Gmail view");
    }
  }

  const observer = new MutationObserver(() => {
    tryApply();
  });

  function start() {
    tryApply();
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
      });
    }
    setTimeout(tryApply, 800);
    setTimeout(tryApply, 2000);
    setTimeout(tryApply, 5000);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "session" && area !== "local") return;
    if (changes[STORAGE_KEY]) tryApply();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
