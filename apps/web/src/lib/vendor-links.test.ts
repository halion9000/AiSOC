import { afterEach, describe, expect, it, vi } from 'vitest';
import { linkableVendors, vendorClientUrl } from './vendor-links';

afterEach(() => vi.unstubAllEnvs());

describe('vendorClientUrl', () => {
  it('builds each tool\'s own client page address from the examples given', () => {
    expect(vendorClientUrl('fieldeffect', '09a136cc-13f7-410e-9017-55fe3750c7b6')).toBe('https://my.fieldeffect.net/organization/09a136cc-13f7-410e-9017-55fe3750c7b6');
    expect(vendorClientUrl('ninjaone', '83')).toBe('https://app.ninjarmm.com/#/customerDashboard/83/overview');
    expect(vendorClientUrl('halopsa', '516')).toBe('https://liveoakit.halopsa.com/customers?mainview=client&inactive=false&hideinternal=false&viewid=0&clientid=516');
    expect(vendorClientUrl('addigy', '18372653-863b-4d31-a6b9-9d7d16497e32')).toBe('https://app.addigy.com/policies/18372653-863b-4d31-a6b9-9d7d16497e32');
    expect(vendorClientUrl('huntress', '415896')).toBe('https://goliveoak.huntress.io/org/415896/command_center?preserve_url_context=true');
    expect(vendorClientUrl('dnsfilter', '5963484')).toBe('https://app.dnsfilter.com/organizations/5963484');
    expect(vendorClientUrl('timus', 'any-customer')).toBe('https://partners.timusnetworks.com/customers?page=1&limit=50');
    expect(vendorClientUrl('itglue', '7713933')).toBe('https://liveoak.itglue.com/7713933');
    expect(vendorClientUrl('datto-saas', '494057')).toBe('https://app.backupify.com/office365/customers/494057');
    expect(vendorClientUrl('blumira', '49368bf5-a906-4d90-99e5-e637405db6c6')).toBe('https://app.blumira.com/49368bf5-a906-4d90-99e5-e637405db6c6/dashboard/summary');
    expect(vendorClientUrl('huntress-sat', '96354')).toBe('https://mycurricula.com/company/96354/dashboard');
  });

  it("ScreenConnect's address names the company group, keeping its own %1F separator and encoding the name", () => {
    expect(vendorClientUrl('screenconnect', 'Airport Security Park')).toBe('https://liveoakit.screenconnect.com/Host#Access/All%20Machines%1FAirport%20Security%20Park');
    expect(vendorClientUrl('screenconnect', 'A&B/Co?x=1#y')).toBe('https://liveoakit.screenconnect.com/Host#Access/All%20Machines%1FA%26B%2FCo%3Fx%3D1%23y');
  });

  it('makes no link for a tool without a template, or an id that is empty, too long or has control characters', () => {
    expect(vendorClientUrl('petra', '5')).toBeNull();
    expect(vendorClientUrl('dropsuite', '16697')).toBeNull();
    expect(vendorClientUrl('ninjaone', '')).toBeNull();
    expect(vendorClientUrl('ninjaone', '  ')).toBeNull();
    expect(vendorClientUrl('ninjaone', 'a'.repeat(201))).toBeNull();
    expect(vendorClientUrl('ninjaone', '1\n2')).toBeNull();
  });

  it('an id can never break out of the address', () => {
    const url = vendorClientUrl('ninjaone', '83/../../evil?x=1')!;
    expect(url.startsWith('https://app.ninjarmm.com/#/customerDashboard/')).toBe(true);
    expect(url).not.toContain('evil?x');
    expect(url).toContain('83%2F..%2F..%2Fevil%3Fx%3D1');
  });

  it('a template set in the environment replaces the built-in one, but only an https one with {id}', () => {
    vi.stubEnv('NEXT_PUBLIC_VENDOR_LINKS', JSON.stringify({ ninjaone: 'https://eu.ninjarmm.com/#/customerDashboard/{id}/overview', halopsa: 'http://insecure.example/{id}', addigy: 'https://x.example/no-id', petra: 'https://h.example/o/{id}' }));
    expect(vendorClientUrl('ninjaone', '83')).toBe('https://eu.ninjarmm.com/#/customerDashboard/83/overview');
    expect(vendorClientUrl('halopsa', '516')).toContain('liveoakit.halopsa.com');
    expect(vendorClientUrl('addigy', '1')).toContain('app.addigy.com');
    expect(vendorClientUrl('petra', '7')).toBe('https://h.example/o/7');
    expect(linkableVendors()).toContain('petra');
  });

  it('ignores an environment value that is not JSON', () => {
    vi.stubEnv('NEXT_PUBLIC_VENDOR_LINKS', 'not json');
    expect(vendorClientUrl('ninjaone', '83')).toBe('https://app.ninjarmm.com/#/customerDashboard/83/overview');
  });
});
