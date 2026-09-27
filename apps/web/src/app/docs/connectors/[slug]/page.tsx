import fs from 'node:fs';
import path from 'node:path';
import matter from 'gray-matter';
import { MDXRemote } from 'next-mdx-remote/rsc';
import Link from 'next/link';
import { ArrowLeft } from 'lucide-react';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';

const DOCS_DIR = path.join(process.cwd(), '..', 'docs', 'docs', 'connectors');

interface PageProps {
  params: Promise<{ slug: string }>;
}

export async function generateStaticParams() {
  if (!fs.existsSync(DOCS_DIR)) return [];
  return fs.readdirSync(DOCS_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((f) => ({ slug: f.replace(/\.md$/, '') }));
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params;
  const filePath = path.join(DOCS_DIR, `${slug}.md`);
  if (!fs.existsSync(filePath)) {
    return { title: 'Connector doc not found' };
  }
  const raw = fs.readFileSync(filePath, 'utf-8');
  const { data } = matter(raw);
  return {
    title: `${data.title ?? slug} - Connector Docs`,
    description: data.description ?? `Setup guide for the ${slug} connector.`,
  };
}

export default async function ConnectorDocPage({ params }: PageProps) {
  const { slug } = await params;
  const filePath = path.join(DOCS_DIR, `${slug}.md`);
  if (!fs.existsSync(filePath)) {
    notFound();
  }
  const raw = fs.readFileSync(filePath, 'utf-8');
  const { content, data } = matter(raw);
  return (
    <main className="min-h-screen bg-[#0a0c14] text-gray-200">
      <div className="mx-auto max-w-4xl px-6 py-12">
        <Link href="/connectors" className="mb-8 inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300 transition-colors">
          <ArrowLeft className="h-3.5 w-3.5" />Back to Connectors
        </Link>
        <header className="mb-10 border-b border-white/10 pb-6">
          <h1 className="text-3xl font-bold text-white md:text-4xl">{data.title ?? slug}</h1>
          {data.description && <p className="mt-3 text-lg text-gray-400">{data.description}</p>}
        </header>
        <article className="prose prose-invert prose-blue max-w-none">
          <MDXRemote source={content} />
        </article>
        <div className="mt-16 border-t border-white/10 pt-8">
          <Link href="/connectors" className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-500">
            <ArrowLeft className="h-3.5 w-3.5" />Back to Connectors
          </Link>
        </div>
      </div>
    </main>
  );
}