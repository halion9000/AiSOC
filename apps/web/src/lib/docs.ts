// B8: default to the fork's published docs on GitHub so out-of-the-box
// installs don't serve broken /docs/* links. Override with
// NEXT_PUBLIC_DOCS_URL for self-hosted or local documentation builds.
export const DOCS_BASE =
  process.env.NEXT_PUBLIC_DOCS_URL ??
  "https://github.com/halion9000/AiSOC/blob/main/docs";

export const docs = (path: string) =>
  `${DOCS_BASE}/${path.replace(/^\//, "")}`;
