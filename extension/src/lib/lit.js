import { GOOGLE_CLIENT_ID, LIT_API_KEY, LIT_PKP_ID } from "./config";

const LIT_API_BASE = "https://api.chipotle.litprotocol.com/core/v1";

async function callLitAction(code, jsParams) {
  const res = await fetch(`${LIT_API_BASE}/lit_action`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": LIT_API_KEY,
    },
    body: JSON.stringify({ code, jsParams }),
  });

  if (res.status === 402) {
    const errBody = await res.text().catch(() => "");
    throw new Error(
      `Lit account has insufficient credits (402 Payment Required). Add funds in the Chipotle Dashboard (card or ETH/USDC/SOL/LITKEY, $5 min). Details: ${errBody}`,
    );
  }

  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`Lit Action HTTP ${res.status}: ${errBody}`);
  }

  const data = await res.json();
  if (data.has_error) {
    throw new Error(data.logs || "Lit Action execution failed");
  }
  return data.response;
}

export async function encryptForRecipient(message) {
  const code = `
    async function main({ pkpId, message }) {
      const ciphertext = await Lit.Actions.encrypt({ pkpId, message });
      return { ciphertext };
    }
  `;

  const result = await callLitAction(code, {
    pkpId: LIT_PKP_ID,
    message,
  });

  return { ciphertext: result.ciphertext };
}

export async function decryptFile({
  ciphertext,
  expectedEmail,
  googleIdToken,
}) {
  const code = `
    async function main({ pkpId, ciphertext, googleIdToken, expectedEmail, googleClientId }) {
      try {
        const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + googleIdToken);
        const payload = await res.json();

        const authorized = !!payload.email &&
          payload.email.toLowerCase() === expectedEmail.toLowerCase() &&
          payload.aud === googleClientId;

        if (!authorized) {
          return { authorized: false };
        }

        const plaintext = await Lit.Actions.decrypt({ pkpId, ciphertext });
        return { authorized: true, plaintext };
      } catch (e) {
        return { authorized: false, error: String(e) };
      }
    }
  `;

  const result = await callLitAction(code, {
    pkpId: LIT_PKP_ID,
    ciphertext,
    googleIdToken,
    expectedEmail,
    googleClientId: GOOGLE_CLIENT_ID,
  });

  if (!result.authorized) {
    throw new Error(
      result.error
        ? `Not authorized: ${result.error}`
        : "Not authorized to decrypt this file",
    );
  }
  return result.plaintext;
}
