import { redirect } from 'next/navigation';

/**
 * The root of this install is the console, not the project's public marketing page (the landing page that used to live here describes the open-source project, pricing and a hosted waitlist,
 * none of which belongs on a private install that other computers on the network now open).
 *
 * Signed out, the console's first request is refused and the browser is sent to /login (see lib/auth-session.ts), so this one redirect covers both cases. The landing page's sections are still in
 * src/components/landing and the other public pages (docs, pricing, blog) are still served at their own addresses.
 */
export default function Home(): never {
  redirect('/dashboard');
}
