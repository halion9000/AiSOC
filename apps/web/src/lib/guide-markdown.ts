/**
 * A small reader for the user guide's own markdown: headings, paragraphs, bullet and numbered lists, tables, rules, and inline bold, italics and code. Not a general markdown engine: the guide
 * is written in this subset on purpose, so it can be shown as real elements (never as injected HTML) with no extra package.
 */

export type Inline = { kind: 'text' | 'b' | 'i' | 'code' | 'new'; text: string };

export type Block =
  | { type: 'h3'; text: string }
  | { type: 'p'; text: string }
  | { type: 'ul'; items: string[] }
  | { type: 'ol'; items: string[] }
  | { type: 'table'; head: string[]; rows: string[][] }
  | { type: 'hr' };

export interface GuideSection {
  id: string;
  title: string;
  blocks: Block[];
}

export interface Guide {
  title: string;
  intro: Block[];
  sections: GuideSection[];
}

/** "3. Connecting tools in CORE" becomes "connecting-tools-in-core": lower case, words joined by dashes, no leading number. */
export function slugOf(title: string): string {
  return title
    .replace(/^\d+\.\s*/, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/** The "(new)" and "(new, API only)" tags the guide puts beside features not yet checked on the live system. */
const NEW_TAG = /\(new(?:[^)]*)\)/g;

function splitNew(text: string, kind: Inline['kind']): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of text.matchAll(NEW_TAG)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ kind, text: text.slice(last, at) });
    out.push({ kind: 'new', text: m[0].slice(1, -1) });
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ kind, text: text.slice(last) });
  return out;
}

/** Bold or italic text can hold code: split that out so its backticks are never shown. */
function withCode(text: string, kind: Inline['kind']): Inline[] {
  const out: Inline[] = [];
  let last = 0;
  for (const m of text.matchAll(/`([^`]+)`/g)) {
    const at = m.index ?? 0;
    if (at > last) out.push(...splitNew(text.slice(last, at), kind));
    out.push({ kind: 'code', text: m[1] });
    last = at + m[0].length;
  }
  if (last < text.length) out.push(...splitNew(text.slice(last), kind));
  return out;
}

/** Split one line of text into plain, bold, italic and code pieces. An unmatched marker is left as the plain text it is. */
export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  const pattern = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*\s][^*]*)\*/g;
  let last = 0;
  for (const m of text.matchAll(pattern)) {
    const at = m.index ?? 0;
    if (at > last) out.push(...splitNew(text.slice(last, at), 'text'));
    if (m[1] !== undefined) out.push({ kind: 'code', text: m[1] });
    else if (m[2] !== undefined) out.push(...withCode(m[2], 'b'));
    else if (m[3] !== undefined) out.push(...withCode(m[3], 'i'));
    last = at + m[0].length;
  }
  if (last < text.length) out.push(...splitNew(text.slice(last), 'text'));
  return out;
}

const isRow = (line: string) => line.trim().startsWith('|');
const isRule = (line: string) => /^-{3,}\s*$/.test(line.trim());
const bullet = (line: string) => /^[-*]\s+(.*)$/.exec(line);
const numbered = (line: string) => /^\d+\.\s+(.*)$/.exec(line);

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((c) => c.trim());
}

/** Read the guide: the "# " heading is the title, each "## " starts a section, everything before the first section is the intro. */
export function parseGuide(markdown: string): Guide {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const guide: Guide = { title: 'Guide', intro: [], sections: [] };
  let current: Block[] = guide.intro;
  let paragraph: string[] = [];

  const flush = () => {
    if (paragraph.length) current.push({ type: 'p', text: paragraph.join(' ') });
    paragraph = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) {
      flush();
      continue;
    }
    if (line.startsWith('# ')) {
      flush();
      guide.title = line.slice(2).trim();
    } else if (line.startsWith('## ')) {
      flush();
      const title = line.slice(3).trim();
      const section: GuideSection = { id: slugOf(title), title, blocks: [] };
      guide.sections.push(section);
      current = section.blocks;
    } else if (line.startsWith('### ')) {
      flush();
      current.push({ type: 'h3', text: line.slice(4).trim() });
    } else if (isRule(line)) {
      flush();
      current.push({ type: 'hr' });
    } else if (isRow(line)) {
      flush();
      const head = cells(line);
      i++; // the |---|---| line
      const rows: string[][] = [];
      while (i + 1 < lines.length && isRow(lines[i + 1])) rows.push(cells(lines[++i]));
      current.push({ type: 'table', head, rows });
    } else if (bullet(line) || numbered(line)) {
      flush();
      const ordered = !!numbered(line);
      const items: string[] = [];
      let at = i;
      while (at < lines.length) {
        const m = ordered ? numbered(lines[at]) : bullet(lines[at]);
        if (!m) break;
        items.push(m[1]);
        at++;
        // a wrapped line of the same item
        while (at < lines.length && lines[at].trim() && /^\s+\S/.test(lines[at]) && !bullet(lines[at].trim()) && !numbered(lines[at].trim())) {
          items[items.length - 1] += ' ' + lines[at].trim();
          at++;
        }
      }
      current.push({ type: ordered ? 'ol' : 'ul', items });
      i = at - 1;
    } else {
      paragraph.push(line.trim());
    }
  }
  flush();
  return guide;
}

/** Everything a block says, as plain text, so a search can look inside it. */
export function blockText(b: Block): string {
  switch (b.type) {
    case 'p':
    case 'h3':
      return b.text;
    case 'ul':
    case 'ol':
      return b.items.join(' ');
    case 'table':
      return [...b.head, ...b.rows.flat()].join(' ');
    default:
      return '';
  }
}

/** The sections that mention every word of ``query`` (case does not matter). An empty query keeps them all. */
export function searchSections(sections: GuideSection[], query: string): GuideSection[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return sections;
  return sections.filter((s) => {
    const hay = (s.title + ' ' + s.blocks.map(blockText).join(' ')).toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
