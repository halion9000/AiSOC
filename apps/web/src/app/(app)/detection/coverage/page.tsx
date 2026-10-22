import { CoverageView } from '@/components/detections/CoverageView';

export const metadata = {
  title: 'MITRE ATT&CK Coverage',
  description:
    "MITRE ATT&CK coverage matrix derived from A.C.O.R.N's shipped detections, broken down by tier (native, imported, community).",
};

export default function CoveragePage() {
  return <CoverageView />;
}
