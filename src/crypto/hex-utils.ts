export function toBuf(hex: string): Uint8Array {
  const h = hex.replace(/\s+/g, '');
  const len = h.length >>> 1;
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    buf[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16);
  }
  return buf;
}

export function toHex(buf: Uint8Array): string {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    out += buf[i]!.toString(16).padStart(2, '0');
  }
  return out.toUpperCase();
}
