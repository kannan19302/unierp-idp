/** Dedicated queue names prevent workers in other UniERP services consuming IdP jobs. */
export const IDENTITY_EMAIL_QUEUE = "identity-email";
export const IDENTITY_EMAIL_DLQ = "identity-email-dead-letter";
