import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { LIT_NETWORK, GOOGLE_CLIENT_ID } from './config';

let litClient;
let connectingPromise;

// Guards against a race condition: if two calls (e.g. encrypt + decrypt,
// or a double-click) both invoke getLitClient() before the first connect()
// resolves, they must share the same in-flight connection instead of one
// of them getting back a client that isn't ready yet.
async function getLitClient() {
  if (litClient) return litClient;
  if (!connectingPromise) {
    const client = new LitNodeClient({
      litNetwork: "datil-dev", // you imported this but hardcoded 'datil-dev' below — use it
      debug: true,
    });
    connectingPromise = client.connect().then(() => {
      litClient = client;
      return litClient;
    }).catch((err) => {
      connectingPromise = null; // let a future call retry instead of being stuck forever
      console.error(err);
      throw err;
    });
  }
  return connectingPromise;
}

// This is the access-control logic. It runs on the Lit nodes themselves
// (not on your server, not on the client) and only authorizes releasing
// the decryption key if the caller's Google ID token belongs to the
// intended recipient's email address.
function buildAccessLitAction() {
  return `
    const go = async () => {
      try {
        const res = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + googleIdToken);
        const payload = await res.json();
        const authorized = !!payload.email &&
          payload.email.toLowerCase() === expectedEmail.toLowerCase() &&
          payload.aud === googleClientId;
        Lit.Actions.setResponse({ response: authorized ? 'true' : 'false' });
      } catch (e) {
        Lit.Actions.setResponse({ response: 'false' });
      }
    };
    go();
  `;
}

export async function encryptForRecipient(bytes) {
  const client = await getLitClient();
  const litActionCode = buildAccessLitAction();
console.log("client",client)
  // NOTE: unifiedAccessControlConditions below is a placeholder shape.
  // Check the current Lit SDK version's docs for the exact encrypt()
  // signature and how it pairs with a custom Lit Action for gating -
  // the API has changed across SDK versions.
  const { ciphertext, dataToEncryptHash } = await client.encrypt({
    dataToEncrypt: bytes,
    unifiedAccessControlConditions: [
      {
        conditionType: 'evmBasic',
        contractAddress: '',
        standardContractType: '',
        chain: 'ethereum',
        method: '',
        parameters: [':userAddress'],
        returnValueTest: { comparator: '=', value: 'placeholder' }
      }
    ]
  });

  return { ciphertext, dataToEncryptHash, litActionCode };
}

export async function decryptFile({ ciphertext, dataToEncryptHash, litActionCode, expectedEmail, googleIdToken }) {
  const client = await getLitClient();

  const sessionSigs = await client.getLitActionSessionSigs({
    litActionCode,
    jsParams: { googleIdToken, expectedEmail, googleClientId: GOOGLE_CLIENT_ID },
    resourceAbilityRequests: [
      {
        resource: { resource: '*', resourcePrefix: 'lit-accesscontrolcondition' },
        ability: 'access-control-condition-decryption'
      }
    ]
  });

  return client.decrypt({ ciphertext, dataToEncryptHash, sessionSigs });
}
