/**
 * Account access rules:
 * - Soft-deleted (deletedAt): stay in DB, cannot login / encrypt / decrypt / receive new encrypted mail.
 * - Blocked: can login, receive new encrypted mail, and decrypt; cannot send/encrypt.
 */

function accountDeniedError(code, message, status = 403) {
  const err = new Error(message);
  err.status = status;
  err.code = code;
  return err;
}

function assertCanLogin(user) {
  if (!user) {
    throw accountDeniedError("ACCOUNT_NOT_FOUND", "Account not found", 401);
  }
  if (user.deletedAt) {
    throw accountDeniedError(
      "ACCOUNT_DELETED",
      "This account was removed and cannot sign in.",
      403,
    );
  }
  // Blocked users may still log in to receive/decrypt mail.
}

function assertCanEncryptOrSend(user) {
  if (!user) {
    throw accountDeniedError("ACCOUNT_NOT_FOUND", "Account not found", 401);
  }
  if (user.deletedAt) {
    throw accountDeniedError(
      "ACCOUNT_DELETED",
      "This account was removed and cannot send or encrypt mail.",
      403,
    );
  }
  if (user.blocked) {
    throw accountDeniedError(
      "ACCOUNT_BLOCKED",
      "This account is blocked and cannot send or encrypt mail.",
      403,
    );
  }
}

function assertCanDecrypt(user) {
  if (!user) {
    throw accountDeniedError("ACCOUNT_NOT_FOUND", "Account not found", 401);
  }
  if (user.deletedAt) {
    throw accountDeniedError(
      "ACCOUNT_DELETED",
      "This account was removed and cannot decrypt mail.",
      403,
    );
  }
  // Blocked users may receive and decrypt encrypted mail.
}

/**
 * Soft-deleted recipients cannot receive new encrypted emails.
 * Blocked recipients can still receive (and then decrypt/access).
 */
function assertCanReceiveEncryptedMail(user) {
  if (!user) return;
  if (user.deletedAt) {
    throw accountDeniedError(
      "RECIPIENT_DELETED",
      "This recipient account was removed and cannot receive new encrypted mail.",
      403,
    );
  }
}

module.exports = {
  assertCanLogin,
  assertCanEncryptOrSend,
  assertCanDecrypt,
  assertCanReceiveEncryptedMail,
};
