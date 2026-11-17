export interface ScanFinding {
  /** The filename passed in options (or the file path, from the CLI). */
  file: string;
  /** 1-based line; 0 for a whole-file finding such as a committed .env. */
  line: number;
  /** 1-based column where the secret starts; 0 for a whole-file finding. */
  column: number;
  /** Which rule matched, e.g. 'github-token', 'hardcoded-secret', 'env-file'. */
  rule: string;
  /** First 4 characters and the length. The full secret is never included. */
  preview: string;
}

export interface ScanOptions {
  /** Used in findings and to enable unquoted `NAME=value` checks for config files (.env, YAML, INI, TOML, .npmrc). */
  filename?: string;
  /** Extra sensitive words, same meaning as in redact(). */
  keys?: readonly string[];
  /** Names that are never treated as sensitive, same meaning as in redact(). */
  allow?: readonly string[];
}

/** Finds likely secrets in source text. Lines containing `keyblob-ignore` are skipped. */
export declare function scanText(text: string, options?: ScanOptions): ScanFinding[];

/** Returns a finding if the file should never be committed (.env, private key files), else null. */
export declare function scanFileName(filename: string): ScanFinding | null;

/** The marker that skips a line: `'keyblob-ignore'`. */
export declare const IGNORE_MARKER: 'keyblob-ignore';
