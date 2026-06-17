/**
 * Decodes hex, octal, and decimal IP addresses (including carry-over / fewer than 4 parts).
 *
 * @param hostname - The hostname/IP string to parse.
 * @returns The parsed IPv4 address as a 4-octet array, or null if invalid.
 */
export function parseIpv4(hostname: string): number[] | null {
  const clean = hostname.trim();
  if (!/^[0-9a-fA-FxX.]*$/.test(clean)) return null;
  const parts = clean.split('.');
  if (parts.length === 0 || parts.length > 4) return null;
  const parsedValues: number[] = [];
  for (const part of parts) {
    if (part === '') return null;
    let val = 0;
    if (part.toLowerCase().startsWith('0x')) {
      val = parseInt(part, 16);
    } else if (part.startsWith('0') && part.length > 1) {
      if (!/^[0-7]+$/.test(part)) return null;
      val = parseInt(part, 8);
    } else {
      if (!/^\d+$/.test(part)) return null;
      val = parseInt(part, 10);
    }
    if (isNaN(val) || val < 0) return null;
    parsedValues.push(val);
  }
  let ipv4Val = 0;
  const len = parsedValues.length;
  if (len === 1) {
    ipv4Val = parsedValues[0];
  } else if (len === 2) {
    if (parsedValues[0] > 255 || parsedValues[1] > 16777215) return null;
    ipv4Val = (parsedValues[0] * 16777216) + parsedValues[1];
  } else if (len === 3) {
    if (parsedValues[0] > 255 || parsedValues[1] > 255 || parsedValues[2] > 65535) return null;
    ipv4Val = (parsedValues[0] * 16777216) + (parsedValues[1] * 65536) + parsedValues[2];
  } else if (len === 4) {
    if (parsedValues[0] > 255 || parsedValues[1] > 255 || parsedValues[2] > 255 || parsedValues[3] > 255) return null;
    ipv4Val = (parsedValues[0] * 16777216) + (parsedValues[1] * 65536) + (parsedValues[2] * 256) + parsedValues[3];
  }
  if (ipv4Val < 0 || ipv4Val > 4294967295) return null;
  const o1 = Math.floor(ipv4Val / 16777216) & 0xff;
  const o2 = Math.floor(ipv4Val / 65536) & 0xff;
  const o3 = Math.floor(ipv4Val / 256) & 0xff;
  const o4 = ipv4Val & 0xff;
  return [o1, o2, o3, o4];
}

/**
 * Normalizes an IPv6 address. Expands double colons (::), and handles IPv4-mapped/compatible IPv6 addresses.
 *
 * @param ip - The IPv6 address to normalize.
 * @returns The normalized IPv6 string or a mapped IPv4 string (prefix 'ipv4:'), or null if invalid.
 */
export function normalizeIpv6(ip: string): string | null {
  const clean = ip.trim().toLowerCase();
  const ipv4Match = clean.match(/^(?:[0-9a-f:]+:)?(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Match) {
    const ipv4Part = ipv4Match[1];
    const parsed = parseIpv4(ipv4Part);
    if (parsed) {
      const prefix = clean.substring(0, clean.length - ipv4Part.length);
      if (prefix === '::ffff:' || prefix === '::' || prefix === '0:0:0:0:0:ffff:') {
        return `ipv4:${parsed.join('.')}`;
      }
    }
  }
  if (!/^[0-9a-f:]+$/.test(clean)) return null;
  const colons = clean.split(':');
  if (colons.length > 8) return null;
  
  let expanded: string[] = [];
  if (clean.includes('::')) {
    if (clean.indexOf('::') !== clean.lastIndexOf('::')) return null;
    const parts = clean.split('::');
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missingCount = 8 - (left.length + right.length);
    if (missingCount < 0) return null;
    const missing = Array(missingCount).fill('0');
    expanded = [...left, ...missing, ...right];
  } else {
    if (colons.length !== 8) return null;
    expanded = colons;
  }
  
  const padded = expanded.map(p => p.padStart(4, '0'));
  const blocks = padded.map(p => parseInt(p, 16));
  
  // Check for IPv4-mapped (::ffff:xxxx:xxxx) or IPv4-compatible (::xxxx:xxxx)
  const isMapped = blocks.slice(0, 5).every(b => b === 0) && blocks[5] === 0xffff;
  const isCompatible = blocks.slice(0, 6).every(b => b === 0) && !(blocks[6] === 0 && blocks[7] === 1); // exclude loopback ::1
  
  if (isMapped || isCompatible) {
    const o1 = (blocks[6] >> 8) & 0xff;
    const o2 = blocks[6] & 0xff;
    const o3 = (blocks[7] >> 8) & 0xff;
    const o4 = blocks[7] & 0xff;
    return `ipv4:${o1}.${o2}.${o3}.${o4}`;
  }
  
  return padded.join(':');
}

/**
 * Validates a target URL against SSRF threats.
 * Checks protocols (only http and https allowed), loopback, private,
 * link-local, multicast, ULA, Carrier-grade NAT, source host network,
 * and IPv4-mapped/compatible IPv6 address ranges.
 * Also checks for IDN homograph attacks (script mixing).
 *
 * @param targetUrl - The URL string to validate.
 * @returns An object indicating if the URL is safe, with an optional reason if unsafe.
 */
export function validateUrl(targetUrl: string): { safe: boolean; reason?: string } {
  try {
    const parsed = new URL(targetUrl);
    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
      return { safe: false, reason: `Forbidden protocol: ${parsed.protocol}` };
    }
    
    // Extract raw hostname from targetUrl to bypass Punycode conversion of the URL parser
    let authority = '';
    const protocolIndex = targetUrl.indexOf('://');
    if (protocolIndex !== -1) {
      const rest = targetUrl.substring(protocolIndex + 3);
      const endIndex = rest.search(/[\/\?#]/);
      authority = endIndex === -1 ? rest : rest.substring(0, endIndex);
    } else {
      authority = targetUrl;
    }
    
    const atIndex = authority.lastIndexOf('@');
    const hostPort = atIndex === -1 ? authority : authority.substring(atIndex + 1);
    
    const lastColon = hostPort.lastIndexOf(':');
    let rawHost = hostPort;
    if (lastColon !== -1) {
      const closingBracket = hostPort.indexOf(']');
      if (closingBracket === -1 || lastColon > closingBracket) {
        rawHost = hostPort.substring(0, lastColon);
      }
    }
    if (rawHost.startsWith('[') && rawHost.endsWith(']')) {
      rawHost = rawHost.substring(1, rawHost.length - 1);
    }
    rawHost = rawHost.toLowerCase();
    
    // homograph check on raw host
    const hasLatin = /[a-zA-Z]/.test(rawHost);
    const hasCyrillic = /[\u0400-\u04FF]/.test(rawHost);
    const hasGreek = /[\u0370-\u03FF]/.test(rawHost);
    if ((hasLatin && hasCyrillic) || (hasLatin && hasGreek) || (hasCyrillic && hasGreek)) {
      return { safe: false, reason: 'Potential IDN homograph attack detected' };
    }

    let hostname = parsed.hostname.toLowerCase();
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      hostname = hostname.substring(1, hostname.length - 1);
    }

    if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '::1' || hostname === '::') {
      let reason = `Blocked loopback/unspecified hostname: ${hostname}`;
      if (hostname === '::1') {
        reason = 'Loopback IPv6 address blocked';
      } else if (hostname === '::') {
        reason = 'Unspecified IPv6 address blocked';
      }
      return { safe: false, reason };
    }

    const ipv4 = parseIpv4(hostname);
    if (ipv4) {
      const [o1, o2, o3, o4] = ipv4;
      if (o1 === 127) return { safe: false, reason: `Loopback IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 10) return { safe: false, reason: `Private IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 172 && o2 >= 16 && o2 <= 31) return { safe: false, reason: `Private IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 192 && o2 === 168) return { safe: false, reason: `Private IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 169 && o2 === 254) return { safe: false, reason: `Link-local IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 100 && o2 >= 64 && o2 <= 127) return { safe: false, reason: `Carrier-grade NAT IP address blocked: ${ipv4.join('.')}` };
      if (o1 === 0) return { safe: false, reason: `Source/current host network IP address blocked: ${ipv4.join('.')}` };
      if (o1 >= 224) return { safe: false, reason: `Multicast/reserved IP address blocked: ${ipv4.join('.')}` };
      return { safe: true };
    }

    const ipv6 = normalizeIpv6(hostname);
    if (ipv6) {
      if (ipv6.startsWith('ipv4:')) {
        const parts = ipv6.substring(5).split('.').map(Number);
        const [o1, o2, o3, o4] = parts;
        if (o1 === 127) return { safe: false, reason: `Loopback IP address blocked: ${parts.join('.')}` };
        if (o1 === 10) return { safe: false, reason: `Private IP address blocked: ${parts.join('.')}` };
        if (o1 === 172 && o2 >= 16 && o2 <= 31) return { safe: false, reason: `Private IP address blocked: ${parts.join('.')}` };
        if (o1 === 192 && o2 === 168) return { safe: false, reason: `Private IP address blocked: ${parts.join('.')}` };
        if (o1 === 169 && o2 === 254) return { safe: false, reason: `Link-local IP address blocked: ${parts.join('.')}` };
        if (o1 === 100 && o2 >= 64 && o2 <= 127) return { safe: false, reason: `Carrier-grade NAT IP address blocked: ${parts.join('.')}` };
        if (o1 === 0) return { safe: false, reason: `Source/current host network IP address blocked: ${parts.join('.')}` };
        if (o1 >= 224) return { safe: false, reason: `Multicast/reserved IP address blocked: ${parts.join('.')}` };
        return { safe: true };
      }
      
      const blocks = ipv6.split(':').map(b => parseInt(b, 16));
      if (blocks.every(b => b === 0)) return { safe: false, reason: 'Unspecified IPv6 address blocked' };
      if (blocks.slice(0, 7).every(b => b === 0) && blocks[7] === 1) return { safe: false, reason: 'Loopback IPv6 address blocked' };
      
      // Link-local: fe80::/10 -> first block starts with fe8, fe9, fea, feb
      const first = blocks[0];
      if (first >= 0xfe80 && first <= 0xfebf) return { safe: false, reason: 'Link-local IPv6 address blocked' };
      // ULA: fc00::/7 -> first block starts with fc or fd
      if (first >= 0xfc00 && first <= 0xfdff) return { safe: false, reason: 'Unique Local IPv6 address blocked' };
      // Multicast: ff00::/8
      if (first >= 0xff00 && first <= 0xffff) return { safe: false, reason: 'Multicast IPv6 address blocked' };
    }

    return { safe: true };
  } catch (e: any) {
    return { safe: false, reason: `Invalid URL format: ${e.message}` };
  }
}
