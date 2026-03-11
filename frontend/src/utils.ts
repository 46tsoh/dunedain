/**
 * Parse a UTC timestamp string from the backend, which may lack a timezone
 * designator (e.g. "2026-03-07T09:22:16.089605" instead of "...Z").
 * Appending "Z" forces JavaScript to interpret it as UTC rather than local
 * time, so toLocaleString() / toLocaleDateString() display the correct
 * local time.
 */
export function parseUTC(ts: string | null | undefined): Date {
  if (!ts) return new Date(NaN);
  // Already has a timezone designator — leave it alone.
  if (ts.endsWith('Z') || ts.includes('+') || /T.*-\d{2}:\d{2}$/.test(ts)) {
    return new Date(ts);
  }
  return new Date(ts + 'Z');
}

export function formatDateTime(ts: string | null | undefined): string {
  return parseUTC(ts).toLocaleString();
}

export function formatDate(ts: string | null | undefined): string {
  return parseUTC(ts).toLocaleDateString();
}
