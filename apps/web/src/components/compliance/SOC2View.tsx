'use client';

// B6 fix: /api/v1/compliance/soc2 does not exist in this build.
// Show an explicit unavailable state instead of sending a doomed request.
export function SOC2View() {
  return (
    <div className="p-8 text-center space-y-3">
      <h2 className="text-lg font-semibold text-gray-200">SOC 2 Compliance Dashboard</h2>
      <p className="text-sm text-gray-400 max-w-xl mx-auto">
        This compliance module is not available in the current AiSOC build.
        The evidence collection, heatmap, and export endpoints have not been
        implemented yet. Enable them by deploying the full compliance service
        or upgrade to a release that includes the SOC 2 automation pipeline.
      </p>
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-800/60 text-xs text-gray-400 border border-gray-700">
        Not available in this build
      </span>
    </div>
  );
}