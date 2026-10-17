'use client';

/** Last resort: an error in the root layout itself. It replaces the layout, so it brings its own <html> and <body> (and cannot rely on the app's CSS). */
export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en">
      <body style={{ background: '#030712', color: '#e5e7eb', fontFamily: 'system-ui, sans-serif', padding: '3rem', textAlign: 'center' }}>
        <h1 style={{ fontSize: '1.25rem' }}>AiSOC hit an error</h1>
        <p style={{ opacity: 0.7 }}>Reload to try again.</p>
        <button onClick={reset} style={{ marginTop: '1rem', padding: '0.5rem 1rem', borderRadius: 6 }}>
          Reload
        </button>
      </body>
    </html>
  );
}
