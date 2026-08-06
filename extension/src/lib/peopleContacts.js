/**
 * Google People API — search contacts by query (textbox text).
 * Uses people:searchContacts + otherContacts:search with `query` param.
 */

const SEARCH_PAGE_SIZE = 30; // API max
const READ_MASK = "names,emailAddresses";
const warmedAccessTokens = new Set();

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

function resultsToSuggestions(data) {
  const out = [];
  for (const row of data?.results || []) {
    out.push(...personToSuggestions(row.person || row));
  }
  return out;
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

/** Google requires an empty-query warmup before search for cache freshness. */
async function ensureSearchWarmed(accessToken) {
  if (warmedAccessTokens.has(accessToken)) return;
  await Promise.allSettled([
    peopleFetch(
      `https://people.googleapis.com/v1/people:searchContacts?query=&readMask=${encodeURIComponent(READ_MASK)}&pageSize=1`,
      accessToken,
    ),
    peopleFetch(
      `https://people.googleapis.com/v1/otherContacts:search?query=&readMask=${encodeURIComponent(READ_MASK)}&pageSize=1`,
      accessToken,
    ),
  ]);
  warmedAccessTokens.add(accessToken);
  if (warmedAccessTokens.size > 20) {
    const first = warmedAccessTokens.values().next().value;
    warmedAccessTokens.delete(first);
  }
}

/**
 * Search Google Contacts + Other contacts for the typed query.
 */
export async function searchGoogleContactEmails(accessToken, query) {
  const q = String(query || "").trim();
  if (!accessToken || !q) return [];

  await ensureSearchWarmed(accessToken);

  const encoded = encodeURIComponent(q);
  const results = [];
  const errors = [];

  const tasks = [
    peopleFetch(
      `https://people.googleapis.com/v1/people:searchContacts?query=${encoded}&readMask=${encodeURIComponent(READ_MASK)}&pageSize=${SEARCH_PAGE_SIZE}`,
      accessToken,
    ).then((data) => {
      results.push(...resultsToSuggestions(data));
    }),
    peopleFetch(
      `https://people.googleapis.com/v1/otherContacts:search?query=${encoded}&readMask=${encodeURIComponent(READ_MASK)}&pageSize=${SEARCH_PAGE_SIZE}`,
      accessToken,
    ).then((data) => {
      results.push(...resultsToSuggestions(data));
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
