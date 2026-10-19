export type UrlCheck = { ok: true; url: string } | { ok: false; error: string };

/**
 * Light, friendly checks before sending a URL to the backend.
 * This is for convenience only: the backend performs the real security validation.
 */
export const normalizeTargetUrl = (raw: string): UrlCheck => {
  const trimmed = raw.trim();
  if (!trimmed) {
    return { ok: false, error: 'Enter a website address, for example https://example.com.' };
  }

  // Accept "example.com" by assuming HTTPS.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed);
  const candidate = hasScheme ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { ok: false, error: "That doesn't look like a valid web address." };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, error: 'Only http:// and https:// addresses can be scanned.' };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, error: 'Remove the username and password from the address.' };
  }
  if (!parsed.hostname.includes('.') && !parsed.hostname.startsWith('[')) {
    return { ok: false, error: 'Enter a full domain name, for example example.com.' };
  }

  return { ok: true, url: candidate };
};
