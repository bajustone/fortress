/**
 * Canonical representation used for persisted and compared email identities.
 *
 * NFC collapses canonically-equivalent Unicode spellings while lowercase
 * makes the product's explicitly case-insensitive email policy deterministic
 * across database collations. Deliberately does not trim: surrounding
 * whitespace is invalid input, not part of identity canonicalization.
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().normalize('NFC');
}
