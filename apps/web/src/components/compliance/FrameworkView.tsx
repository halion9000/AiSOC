'use client';

// B6 fix: /api/v1/compliance/{framework}/heatmap|export|collect do not exist
// in this build. Show an explicit unavailable state instead of sending doomed
// requests that would 404 against the catch-all API rewrite.
interface Props {
  framework: string;
}

export function FrameworkView({ framework }: Props) {
  return (
    <div className="p-8 text-center space-y-3">
      <h2 className="text-lg font-semibold text-gray-200">
        {framework.toUpperCase()} Compliance Dashboard
      </h2>
      <p className="text-sm text-gray-400 max-w-xl mx-auto">
        The compliance evidence pipeline for <code>{framework}</code> is not
        available in the current AiSOC build. Heatmap, export, and collection
        endpoints have not been implemented yet. Deploy the full compliance
        service or upgrade to a release that includes this framework's
        automation to enable it.
      </p>
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-800/60 text-xs text-gray-400 border border-gray-700">
        Not available in this build
      </span>
    </div>
  );
}