/**
 * Hunt searches the alerts A.C.O.R.N holds (see hunt_alert_search.py: plain words, "quoted phrases", field:value, a leading - for not).
 * A plain-language question is turned into that syntax here, in the browser, so what runs is exactly what the editor shows.
 */

const STOP = new Set(
  ('a an the any all some show me list find get give what which who whom whose is are was were be been do does did have has had there their '
    + 'for at in on with without of to from and or but not no that this these those it its my our your i we you they them any anything something events event '
    + 'alerts alert please can could would should happened happening recent recently latest new today lately over past last severity status').split(' '),
);
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES: Record<string, string> = { open: 'open', new: 'new', closed: 'closed', resolved: 'resolved', investigating: 'investigating' };

function stem(w: string): string {
  return w.length > 4 && w.endsWith('s') && !w.endsWith('ss') && !w.endsWith('us') ? w.slice(0, -1) : w;
}

/** "any suspicious logins at live oak" -> `suspicious login client:"live oak"`. Empty when nothing searchable is left. */
export function questionToAlertSearch(question: string): string {
  let text = (question || '').trim().replace(/[?!.]+$/, '');
  const parts: string[] = [];
  for (const m of text.matchAll(/"([^"]+)"/g)) parts.push(`"${m[1]}"`);
  text = text.replace(/"[^"]*"/g, ' ');
  const org = /\b(?:at|for|in|of)\s+(?:the\s+)?((?:[A-Za-z0-9&'-]+\s*){1,4})$/i.exec(text);
  let client = '';
  if (org) {
    const words = org[1].trim().split(/\s+/);
    if (words.some((w) => !STOP.has(w.toLowerCase()))) {
      client = words.join(' ');
      text = text.slice(0, org.index);
    }
  }
  for (const raw of text.toLowerCase().split(/[^a-z0-9@._:-]+/).filter(Boolean)) {
    if (SEVERITIES.includes(raw)) parts.push(`severity:${raw}`);
    else if (STATUSES[raw]) parts.push(`status:${STATUSES[raw]}`);
    else if (!STOP.has(raw)) parts.push(stem(raw));
  }
  if (client) parts.push(`client:"${client}"`);
  return [...new Set(parts)].join(' ');
}
