// Placing contract `edits` on a string. Spans are [start, end) code-point offsets into the string the tool
// aligned (usually the name's first label, so offset 0 of the display); we search label boundaries
// for the offset where every edit's text actually sits, and give up gracefully if none fits.
import type { Edit } from "./types";

export interface Seg { text: string; edit?: Edit }

function fits(chars: string[], edits: Edit[], off: number, side: "candidate" | "genuine"): boolean {
  return edits.every((e) => {
    const [s, t] = side === "candidate" ? e.candidate_span : e.genuine_span;
    const want = side === "candidate" ? e.candidate : e.genuine;
    if (!want) return true;           // an insertion on the other side: nothing to find here
    return chars.slice(off + s, off + t).join("") === want;
  });
}

/** Segments of `text` with each edit's span marked, or null if the spans don't fit anywhere. */
export function segment(text: string, edits: Edit[] | undefined, side: "candidate" | "genuine" = "candidate"): Seg[] | null {
  const chars = Array.from(text);
  if (!edits?.length) return [{ text }];
  const starts = [0, ...chars.flatMap((c, k) => (c === "." || c === "-" ? [k + 1] : []))];
  const off = starts.find((o) => fits(chars, edits, o, side));
  if (off === undefined) return null;
  const marks: (Edit | undefined)[] = new Array(chars.length).fill(undefined);
  for (const e of edits) {
    const [s, t] = side === "candidate" ? e.candidate_span : e.genuine_span;
    for (let k = off + s; k < off + t && k < chars.length; k++) marks[k] = e;
  }
  const out: Seg[] = [];
  chars.forEach((c, k) => {
    const prev = out[out.length - 1];
    if (prev && prev.edit === marks[k]) prev.text += c;
    else out.push({ text: c, edit: marks[k] });
  });
  return out;
}

/** Non-ASCII characters of a name, with code points ("а" → U+0430). */
export function foreignChars(text: string): { ch: string; cp: string; at: number }[] {
  return Array.from(text).flatMap((ch, at) => {
    const n = ch.codePointAt(0) ?? 0;
    return n > 127 ? [{ ch, at, cp: "U+" + n.toString(16).toUpperCase().padStart(4, "0") }] : [];
  });
}
