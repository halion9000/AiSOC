'use client';

// B6 fix: /api/v1/easm/certificates does not exist in this build (only
// /easm/assets and /easm/drift are served). Show an explicit unavailable
// state instead of sending a doomed request that would 404.
export function EASMView() {
  return (
    <div className="p-8 text-center space-y-3">
      <h1 className="text-xl font-semibold text-gray-100">
        External Attack Surface Management
      </h1>
      <p className="text-sm text-gray-400 max-w-xl mx-auto">
        The EASM certificate inventory is not available in the current AiSOC
        build. Asset discovery and drift detection remain functional via
        <code>/api/v1/easm/assets</code> and <code>/api/v1/easm/drift</code>,
        but the certificates endpoint has not been implemented yet. Deploy
        the full EASM pipeline or upgrade to enable it.
      </p>
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-gray-800/60 text-xs text-gray-400 border border-gray-700">
        Certificate module not available in this build
      </span>
    </div>
  );
}