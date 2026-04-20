'use strict';

/**
 * Public -> internal option normalizer. Consumers pass the documented option
 * names (integrityChecks, antiDebug, junkRatio, ...); the pipeline internally
 * uses a slightly different shape (useIntegrity, etc.). This module is the
 * single source of truth for that mapping and for defaulting.
 *
 * Rules:
 *   - Public names win if both are passed (e.g. passing integrityChecks: false
 *     along with useIntegrity: true results in integrity disabled).
 *   - Unknown keys pass through untouched so internal escape hatches keep
 *     working without being documented.
 *   - resolvedOptions.integrityDefault lets individual obfuscators pick a
 *     wrapper-appropriate default (HTML -> true, external JS/CSS -> false).
 */

const DEFAULTS = {
  antiDebug: true,
  devtoolsTrap: true,
  integrityChecks: undefined,
  pbkdf2Iterations: 250000,
  closeUrl: '',
  rewriteHtml: '',
  junkRatio: 2.0,
  stripSourceMaps: true,
  keyFragments: 8,
  cipherFragments: [24, 48],
  decoys: 2,
  nameStyle: 'hex',
  maxBytes: 5 * 1024 * 1024,
  include: null,
  exclude: null,
  onError: null,
  testMode: false,
};

function toMatcher(value) {
  if (value == null) return null;
  if (typeof value === 'function') return value;
  if (value instanceof RegExp) return url => value.test(url);
  if (Array.isArray(value)) {
    const ms = value.map(toMatcher).filter(Boolean);
    return url => ms.some(m => m(url));
  }
  if (typeof value === 'string') {
    return url => url.indexOf(value) !== -1;
  }
  return null;
}

function normalizeOptions(userOptions = {}) {
  const merged = { ...DEFAULTS, ...userOptions };

  // integrityChecks is the public spelling; useIntegrity is the internal one.
  // If either is explicitly false, integrity is off regardless of the other
  // (so middleware can safely force-disable for external JS/CSS even when the
  // caller requested integrity on the HTML path). Otherwise honor whichever is
  // defined; fall through to undefined so each obfuscator picks its own default.
  let integrity;
  if (userOptions.integrityChecks === false || userOptions.useIntegrity === false) {
    integrity = false;
  } else if (userOptions.integrityChecks !== undefined) {
    integrity = !!userOptions.integrityChecks;
  } else if (userOptions.useIntegrity !== undefined) {
    integrity = !!userOptions.useIntegrity;
  } else {
    integrity = undefined;
  }
  merged.integrityChecks = integrity;
  merged.useIntegrity = integrity;

  merged._includeMatcher = toMatcher(merged.include);
  merged._excludeMatcher = toMatcher(merged.exclude);

  return merged;
}

module.exports = { normalizeOptions, DEFAULTS };
