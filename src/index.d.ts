/** The mask string substituted for sensitive values. */
export declare const REDACTED: '[REDACTED]';

export interface RedactOptions {
  /**
   * Extra sensitive words, matched like the built-ins: case-insensitive, against a
   * word or run of adjacent words in the key, or the whole key. `'ssnLast4'` masks
   * `ssnLast4` and `tenant_ssn_last4`.
   */
  keys?: readonly string[];
  /**
   * Keys that are never masked. Exact whole-key match, ignoring case and `_`/`-`,
   * so `'session'` keeps `session` but still masks `sessionId`. Wins over everything.
   */
  allow?: readonly string[];
  /** Nesting deeper than this becomes `'[MaxDepth]'`. Default 100. */
  maxDepth?: number;
  /** Objects visited per call before the rest becomes `'[Truncated]'`. Default 10000. */
  maxNodes?: number;
  /** Items kept per array; the rest becomes one `'[Truncated: N more items]'` entry. Default 100. */
  maxArrayLength?: number;
}

/**
 * Returns a redacted deep copy safe to log. The result is NOT the same type as
 * the input (class instances lose their prototype, Map/Set become {}, sensitive
 * values become strings), so it is typed as unknown.
 *
 * Options are read once per options object. To change them, pass a new object,
 * or use createRedactor().
 */
export declare function redact(input: unknown, options?: RedactOptions): unknown;

/** Builds a reusable redact function for one set of options. Throws TypeError on invalid options. */
export declare function createRedactor(options?: RedactOptions): (input: unknown) => unknown;
