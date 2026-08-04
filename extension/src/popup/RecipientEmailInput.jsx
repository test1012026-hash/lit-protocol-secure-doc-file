import React, { useEffect, useRef, useState } from "react";
import { getPeopleAccessToken } from "../lib/googleAuth";
import {
  filterContactEmails,
  loadGoogleContactEmails,
} from "../lib/peopleContacts";
import { normalizeEmail } from "../lib/email";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

function isValidEmail(value) {
  return EMAIL_RE.test(String(value || "").trim());
}

export default function RecipientEmailInput({
  auth,
  value = [],
  onChange,
  disabled,
  placeholder = "Add recipient email",
}) {
  const emails = Array.isArray(value) ? value : [];
  const [query, setQuery] = useState("");
  const [suggestions, setSuggestions] = useState([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [hint, setHint] = useState("");
  const [needsContacts, setNeedsContacts] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const wrapRef = useRef(null);
  const inputRef = useRef(null);
  const contactsCache = useRef(null);
  const loadingContacts = useRef(false);
  const reqId = useRef(0);

  const selectedSet = new Set(emails.map((e) => normalizeEmail(e)));

  useEffect(() => {
    const onDoc = (e) => {
      if (!wrapRef.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  async function ensureContactsLoaded({ force = false } = {}) {
    if (!force && contactsCache.current) return contactsCache.current;
    if (loadingContacts.current) {
      for (let i = 0; i < 50; i++) {
        await new Promise((r) => setTimeout(r, 100));
        if (contactsCache.current) return contactsCache.current;
      }
    }

    loadingContacts.current = true;
    setHint("Connecting Google Contacts…");
    setNeedsContacts(false);
    try {
      const token = await getPeopleAccessToken(auth.token, auth);
      const contacts = await loadGoogleContactEmails(token);
      contactsCache.current = contacts;
      setNeedsContacts(false);
      setHint("");
      return contacts;
    } catch (err) {
      contactsCache.current = null;
      if (
        err?.code === "CONTACTS_SCOPE_REQUIRED" ||
        err?.code === "PEOPLE_API_DISABLED"
      ) {
        setNeedsContacts(true);
      }
      throw err;
    } finally {
      loadingContacts.current = false;
    }
  }

  const buildMenu = (q, contactRows) => {
    const typed = String(q || "").trim();
    const rows = (contactRows || []).filter(
      (item) => !selectedSet.has(normalizeEmail(item.email)),
    );
    const typedNorm = typed ? normalizeEmail(typed) : "";
    const typedAlready =
      typedNorm && selectedSet.has(typedNorm);
    const typedInSuggestions = rows.some(
      (r) => normalizeEmail(r.email) === typedNorm,
    );

    if (typed && isValidEmail(typed) && !typedAlready && !typedInSuggestions) {
      rows.unshift({
        email: typedNorm,
        name: "Use this email",
        isCustom: true,
      });
    } else if (typed.length >= 2 && !rows.length && !typedAlready) {
      rows.push({
        email: typed,
        name: isValidEmail(typed)
          ? "Use this email"
          : "Keep typing a valid email…",
        isCustom: true,
        disabled: !isValidEmail(typed),
      });
    }
    return rows.slice(0, 10);
  };

  useEffect(() => {
    const q = String(query || "").trim();
    if (disabled || q.length < 2) {
      setSuggestions([]);
      setOpen(false);
      setLoading(false);
      setActiveIndex(-1);
      return undefined;
    }

    const id = ++reqId.current;
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        let contacts = contactsCache.current || [];
        try {
          contacts = await ensureContactsLoaded();
        } catch {
          contacts = [];
        }
        if (reqId.current !== id) return;
        const rows = buildMenu(q, filterContactEmails(contacts, q, 8));
        setSuggestions(rows);
        setOpen(rows.length > 0);
        setActiveIndex(rows.length ? 0 : -1);
        if (!rows.length) setHint("");
      } finally {
        if (reqId.current === id) setLoading(false);
      }
    }, 180);

    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, emails, auth?.token, disabled]);

  const addEmail = (raw) => {
    const email = normalizeEmail(String(raw || "").trim());
    if (!isValidEmail(email)) {
      setHint("Enter a valid email address.");
      return;
    }
    if (selectedSet.has(email)) {
      setHint("That email is already added.");
      setQuery("");
      setSuggestions([]);
      setOpen(false);
      return;
    }
    onChange([...emails, email]);
    setQuery("");
    setSuggestions([]);
    setOpen(false);
    setActiveIndex(-1);
    setHint("");
    requestAnimationFrame(() => inputRef.current?.focus());
  };

  const removeEmail = (email) => {
    const target = normalizeEmail(email);
    onChange(emails.filter((e) => normalizeEmail(e) !== target));
  };

  const pickSuggestion = (item) => {
    if (item?.disabled) return;
    addEmail(item.email);
  };

  const onKeyDown = (e) => {
    if (e.key === "Backspace" && !query && emails.length) {
      removeEmail(emails[emails.length - 1]);
      return;
    }
    if (e.key === "Escape") {
      setOpen(false);
      return;
    }
    if (e.key === "ArrowDown" && open && suggestions.length) {
      e.preventDefault();
      setActiveIndex((i) => (i + 1) % suggestions.length);
      return;
    }
    if (e.key === "ArrowUp" && open && suggestions.length) {
      e.preventDefault();
      setActiveIndex((i) => (i <= 0 ? suggestions.length - 1 : i - 1));
      return;
    }
    if (e.key === "Enter" || e.key === "Tab" || e.key === ",") {
      if (open && activeIndex >= 0 && suggestions[activeIndex] && !suggestions[activeIndex].disabled) {
        e.preventDefault();
        pickSuggestion(suggestions[activeIndex]);
        return;
      }
      if (query.trim()) {
        e.preventDefault();
        addEmail(query);
      }
    }
  };

  const connectContacts = async () => {
    setLoading(true);
    setHint("Waiting for Google permission…");
    try {
      contactsCache.current = null;
      await ensureContactsLoaded({ force: true });
      if (query.trim().length >= 2) {
        const rows = buildMenu(
          query,
          filterContactEmails(contactsCache.current || [], query, 8),
        );
        setSuggestions(rows);
        setOpen(rows.length > 0);
      }
    } catch (err) {
      setHint(err.message || "Could not connect Google Contacts.");
      setNeedsContacts(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="recipient-suggest" ref={wrapRef}>
      <div
        className={`recipient-chip-field${disabled ? " is-disabled" : ""}`}
        onClick={() => inputRef.current?.focus()}
      >
        {emails.map((email) => (
          <span className="recipient-chip" key={email}>
            <span className="recipient-chip-text">{email}</span>
            <button
              type="button"
              className="recipient-chip-remove"
              aria-label={`Remove ${email}`}
              disabled={disabled}
              onClick={(e) => {
                e.stopPropagation();
                removeEmail(email);
              }}
            >
              ×
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          className="recipient-chip-input"
          placeholder={emails.length ? "" : placeholder}
          value={query}
          disabled={disabled}
          autoComplete="off"
          onChange={(e) => setQuery(e.target.value.replace(/,/g, ""))}
          onKeyDown={onKeyDown}
          onFocus={() => {
            if (suggestions.length) setOpen(true);
          }}
        />
      </div>

      {loading && (
        <p className="recipient-suggest-status">Searching contact emails…</p>
      )}
      {!loading && hint && (
        <p className="recipient-suggest-status">{hint}</p>
      )}
      {needsContacts && (
        <button
          type="button"
          className="btn btn-secondary"
          style={{ marginTop: 8, marginBottom: 4 }}
          disabled={disabled || loading}
          onClick={connectContacts}
        >
          Allow Google Contacts
        </button>
      )}

      {open && suggestions.length > 0 && (
        <ul className="recipient-suggest-list" role="listbox">
          {suggestions.map((item, index) => (
            <li key={`${item.isCustom ? "custom" : "c"}:${item.email}`}>
              <button
                type="button"
                role="option"
                aria-selected={index === activeIndex}
                disabled={item.disabled}
                className={
                  index === activeIndex
                    ? "recipient-suggest-item is-active"
                    : "recipient-suggest-item"
                }
                onMouseDown={(e) => e.preventDefault()}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => pickSuggestion(item)}
              >
                <span className="recipient-suggest-name">
                  {item.isCustom ? item.name : item.name}
                </span>
                <span className="recipient-suggest-email">
                  {item.isCustom && isValidEmail(item.email)
                    ? `Add “${item.email}”`
                    : item.email}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
