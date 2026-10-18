import { describe, expect, it } from 'vitest';
import { confidenceFraction, normalizeAlert } from './api';

describe('confidence is shown as a fraction of one, however the API sent it', () => {
  it('reads a whole number from 0 to 100 as a percentage (47 is 47%, not 4700%)', () => {
    expect(confidenceFraction(47)).toBe(0.47);
    expect(confidenceFraction(100)).toBe(1);
    expect(confidenceFraction(0)).toBe(0);
  });

  it('leaves a fraction alone, and never goes above 1', () => {
    expect(confidenceFraction(0.62)).toBe(0.62);
    expect(confidenceFraction(1)).toBe(1);
    expect(confidenceFraction(250)).toBe(1);
  });

  it('says nothing for a value that is not a usable number', () => {
    expect(confidenceFraction(undefined)).toBeUndefined();
    expect(confidenceFraction(-5)).toBeUndefined();
    expect(confidenceFraction(Number.NaN)).toBeUndefined();
  });

  it('an alert from the API with confidence 47 reaches the page as 0.47', () => {
    const alert = normalizeAlert({ id: 'a', title: 't', confidence: 47, confidence_label: 'medium' });
    expect(alert.confidenceScore).toBe(0.47);
    expect(Math.round((alert.confidenceScore ?? 0) * 100)).toBe(47);
  });

  it('an explicit confidence_score already between 0 and 1 is kept', () => {
    expect(normalizeAlert({ id: 'a', confidence_score: 0.8 }).confidenceScore).toBe(0.8);
  });
});
