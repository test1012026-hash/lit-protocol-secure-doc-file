/**
 * Google People API — email autocomplete from Contacts / Other contacts.
 */

function personToSuggestions(person) {
  const name =
    person?.names?.[0]?.displayName ||
    person?.names?.[0]?.unstructuredName ||
    "";
  const emails = (person?.emailAddresses || [])
    .map((e) => String(e.value || "").trim().toLowerCase())
    .filter((email) => email.includes("@"));
  return emails.map((email) => ({
    email,
    name: name || email.split("@")[0],
  }));
}

function dedupeByEmail(items) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = item.email.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

export function filterContactEmails(items, query, limit = 8) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return [];
  return dedupeByEmail(items)
    .filter(
      (item) =>
        item.email.includes(q) || item.name.toLowerCase().includes(q),
    )
    .sort((a, b) => {
      const aStarts =
        a.email.startsWith(q) || a.name.toLowerCase().startsWith(q);
      const bStarts =
        b.email.startsWith(q) || b.name.toLowerCase().startsWith(q);
      if (aStarts !== bStarts) return aStarts ? -1 : 1;
      return a.email.localeCompare(b.email);
    })
    .slice(0, limit);
}

function classifyPeopleError(status, body, bodyText) {
  const msg = String(body?.error?.message || bodyText || `HTTP ${status}`);
  if (/has not been used|is disabled|API has not been|SERVICE_DISABLED/i.test(msg)) {
    const err = new Error(
      "People API is disabled. Google Cloud Console → Enable “People API”, then click Allow Google Contacts again.",
    );
    err.code = "PEOPLE_API_DISABLED";
    return err;
  }
  if (
    status === 401 ||
    status === 403 ||
    /insufficient|ACCESS_TOKEN_SCOPE|authentication scopes/i.test(msg)
  ) {
    const err = new Error(
      "Google Contacts permission missing. Click “Allow Google Contacts” and approve Contacts access.",
    );
    err.code = "CONTACTS_SCOPE_REQUIRED";
    err.detail = body;
    return err;
  }
  const err = new Error(msg);
  err.code = "PEOPLE_API_ERROR";
  err.status = status;
  return err;
}

async function peopleFetch(url, accessToken) {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  const bodyText = await res.text().catch(() => "");
  let body = null;
  try {
    body = bodyText ? JSON.parse(bodyText) : null;
  } catch {
    body = { raw: bodyText };
  }

  if (!res.ok) {
    throw classifyPeopleError(res.status, body, bodyText);
  }
  return body || {};
}

/**
 * Load contact emails (Connections + Other contacts).
 */
export async function loadGoogleContactEmails(accessToken) {
  if (!accessToken) return [];

  const results = [];
  const errors = [];

  const tasks = [
    peopleFetch(
      "https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses&pageSize=200&sortOrder=FIRST_NAME_ASCENDING",
      accessToken,
    ).then((data) => {
      for (const person of data.connections || []) {
        results.push(...personToSuggestions(person));
      }
    }),
    peopleFetch(
      "https://people.googleapis.com/v1/otherContacts?readMask=names,emailAddresses&pageSize=200",
      accessToken,
    ).then((data) => {
      for (const person of data.otherContacts || []) {
        results.push(...personToSuggestions(person));
      }
    }),
  ];

  const settled = await Promise.allSettled(tasks);
  for (const item of settled) {
    if (item.status === "rejected") errors.push(item.reason);
  }

  if (!results.length && errors.length) {
    const disabled = errors.find((e) => e?.code === "PEOPLE_API_DISABLED");
    const scopeErr = errors.find((e) => e?.code === "CONTACTS_SCOPE_REQUIRED");
    throw disabled || scopeErr || errors[0];
  }

  return dedupeByEmail(results);
}
