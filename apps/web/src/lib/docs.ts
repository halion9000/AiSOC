export const DOCS_BASE =
  process.env.NEXT_PUBLIC_DOCS_URL ?? "/docs";

export const docs = (path: string) =>
  `${DOCS_BASE}/${path.replace(/^\//, "")}`;
