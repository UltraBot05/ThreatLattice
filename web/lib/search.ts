/**
 * Turns the search box text into a MySQL full-text query (BOOLEAN MODE) on
 * cve.description. Pure function, no database access, so pages can use it
 * too (e.g. to skip a request that would only be rejected).
 *
 * InnoDB rules this has to respect (checked on our data, 2026-11-02):
 * - Words shorter than innodb_ft_min_token_size (3) are not indexed.
 * - The 36 default stopwords are not indexed either. A REQUIRED stopword
 *   never matches: "+the +php" returns 0 rows, so these words are dropped.
 * - Operators (+ - * " ( ) ~ < > @) typed by the user are stripped: only
 *   letters, digits and "_" survive, and we add the operators ourselves.
 */

/** INFORMATION_SCHEMA.INNODB_FT_DEFAULT_STOPWORD (MySQL 8.0). */
const STOPWORDS = new Set(
  "a about an are as at be by com de en for from how i in is it la of on or that the this to und was what when where who will with www".split(
    " ",
  ),
);
const MIN_LEN = 3;
const MAX_TERMS = 10;

export type SearchPlan =
  // "CVE-2024-3400" or a start of one ("CVE-2024-34"): a PK range scan. A
  // complete-looking ID is still a prefix (CVE-2024-34 is real, and so is
  // CVE-2024-34000), so callers sort the shortest, i.e. exact, match first.
  | { kind: "id"; prefix: string }
  | { kind: "fulltext"; against: string; terms: string[] }
  | { kind: "empty" }; // nothing searchable left (only short words / stopwords)

export function planSearch(raw: string): SearchPlan {
  const q = raw.trim();
  const upper = q.toUpperCase();
  if (/^CVE-\d{4}(-\d*)?$/.test(upper)) return { kind: "id", prefix: upper };

  const words = q.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? [];
  const terms = [...new Set(words)].filter((w) => w.length >= MIN_LEN && !STOPWORDS.has(w)).slice(0, MAX_TERMS);
  if (terms.length === 0) return { kind: "empty" };
  // Every word is required (+) and matches as a prefix (*): "injec" finds "injection".
  return { kind: "fulltext", against: terms.map((t) => `+${t}*`).join(" "), terms };
}
