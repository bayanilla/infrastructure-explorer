export const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
export const pct = x => `${Math.round((x || 0) * 100)}%`;
export const asLabel = (asn, name) => `<span class="asn">AS${esc(asn)}</span>${name ? `<span class="nm">${esc(name)}</span>` : ""}`;
export const nf = n => (typeof n === "number" ? n.toLocaleString("en-US") : "unknown");
export const plural = (n, one, many) => `${nf(n)} ${n === 1 ? one : (many || one + "s")}`;
export function csvCell(v){
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}

export function toCSV(header, rows){ return [header, ...rows].map(r => r.map(csvCell).join(",")).join("\r\n") + "\r\n"; }


export function stamp(obj){ return (obj.meta.generated_utc || "").replace(/[:]/g, "").replace("T", "-").replace("Z", ""); }
