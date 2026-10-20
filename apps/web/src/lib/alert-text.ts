import { parseInline, type Inline } from './guide-markdown';

/**
 * Reads the text vendors put in an alert or case description (Huntress, Field Effect and others send a light markdown with tables, "**Heading**" lines and "<br/>" tags) into blocks a page can lay out,
 * instead of one unbroken paragraph. Not a markdown engine: it only knows what those vendors send.
 */
export type TextBlock =
  | { type: 'facts'; rows: Array<[string, Inline[]]> }
  | { type: 'heading'; text: string }
  | { type: 'p'; text: Inline[] }
  | { type: 'list'; items: Inline[][] }
  | { type: 'rule' };

const cleanTags = (s: string) =>
  s
    .replace(/<br\s*\/?>/gi, ' ')
    .replace(/<\/?[a-z][^>]*>/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

const isRow = (l: string) => l.trim().startsWith('|');
const isRule = (l: string) => /^-{3,}\s*$/.test(l.trim());
const isSeparator = (l: string) => /^\|?[\s:|-]+\|?$/.test(l.trim()) && l.includes('-');
const cellsOf = (l: string) =>
  l
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => cleanTags(c));
const headingOf = (l: string) => /^\*\*([^*]{1,80})\*\*:?$/.exec(l.trim())?.[1]?.trim() ?? null;
const bulletOf = (l: string) => /^[-*]\s+(.*)$/.exec(l.trim())?.[1] ?? null;
/** A short "Label: value" line, as in "Client: Acme" or "Host: PC-01". */
const factOf = (l: string): [string, string] | null => {
  const m = /^([A-Z][A-Za-z0-9 /()-]{1,38}):\s+(\S.*)$/.exec(l.trim());
  return m ? [m[1], m[2]] : null;
};

export function parseAlertText(raw: string): TextBlock[] {
  const lines = raw.replace(/\r\n/g, '\n').split('\n');
  const out: TextBlock[] = [];
  let para: string[] = [];
  const flush = () => {
    const text = cleanTags(para.join(' '));
    para = [];
    if (text) out.push({ type: 'p', text: parseInline(text) });
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) {
      flush();
      continue;
    }
    if (isRule(trimmed)) {
      flush();
      out.push({ type: 'rule' });
      continue;
    }
    const head = headingOf(trimmed);
    if (head) {
      flush();
      out.push({ type: 'heading', text: head });
      continue;
    }
    if (isRow(trimmed)) {
      flush();
      const rows: string[][] = [];
      while (i < lines.length && isRow(lines[i])) {
        if (!isSeparator(lines[i])) rows.push(cellsOf(lines[i]));
        i++;
      }
      i--;
      // The empty header row vendors put above the separator carries nothing.
      const real = rows.filter((r) => r.some((c) => c !== ''));
      if (real.length > 0 && real.every((r) => r.length === 2)) out.push({ type: 'facts', rows: real.map((r) => [r[0], parseInline(r[1])]) });
      else if (real.length > 0) out.push({ type: 'facts', rows: real.map((r) => [r[0], parseInline(r.slice(1).filter(Boolean).join(' · '))]) });
      continue;
    }
    if (bulletOf(trimmed) !== null) {
      flush();
      const items: Inline[][] = [];
      while (i < lines.length && bulletOf(lines[i]) !== null) {
        items.push(parseInline(cleanTags(bulletOf(lines[i]) as string)));
        i++;
      }
      i--;
      out.push({ type: 'list', items });
      continue;
    }
    // Two or more "Label: value" lines in a row read as a fact list; a single one is just a sentence.
    if (para.length === 0 && factOf(trimmed) && i + 1 < lines.length && factOf(lines[i + 1])) {
      const rows: Array<[string, Inline[]]> = [];
      while (i < lines.length && factOf(lines[i])) {
        const [k, v] = factOf(lines[i]) as [string, string];
        rows.push([k, parseInline(cleanTags(v))]);
        i++;
      }
      i--;
      out.push({ type: 'facts', rows });
      continue;
    }
    para.push(trimmed);
  }
  flush();
  // A tag-only paragraph ("<br/>") leaves nothing behind, and two rules in a row are one.
  return out.filter((b, idx) => !(b.type === 'rule' && out[idx - 1]?.type === 'rule'));
}
