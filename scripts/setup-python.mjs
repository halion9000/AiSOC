#!/usr/bin/env node
/**
 * setup-python.mjs — create a cross-service .venv-verify for local verification.
 *
 * Creates `.venv-verify/` at the repo root with Python 3.12 (or whatever
 * `python3.12` / `py -3.12` resolves to) and pip-installs exactly the
 * dependency lists declared in `.github/workflows/ci.yml`:
 *
 *   - OPENAPI_DEPS  (minimal set for `app.openapi()` smoke)
 *   - API_DEPS      (full api service runtime + test deps)
 *   - AGENTS_DEPS   (agents-specific: langchain, langgraph, respx, …)
 *
 * Packages that cannot install on Windows (e.g. aiokafka, clickhouse-driver)
 * are gated with PEP 508 environment markers so the script succeeds on any
 * platform. After installation it runs the same OpenAPI import check that
 * `verify.mjs` uses, proving the venv is functional.
 *
 * Usage:
 *   node scripts/setup-python.mjs          # create / reuse .venv-verify
 *   node scripts/setup-python.mjs --recreate  # delete and recreate
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = new Set(process.argv.slice(2));
const recreate = argv.has("--recreate");
const venvDir = path.join(root, ".venv-verify");
const isWin = process.platform === "win32";

const run = (cmd, args, opts = {}) => {
  // On Windows, shell: true is needed for .cmd/.bat files (pnpm, npm) but
  // BREAKS absolute-path executables like .venv\Scripts\python.exe because
  // cmd.exe re-parses the path and fails with "system cannot find the file".
  // Use shell only when the command is a bare name (no path separators).
  const needsShell = isWin && !cmd.includes("/") && !cmd.includes("\\");
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? root,
    encoding: "utf8",
    shell: needsShell,
    stdio: opts.stdio ?? "inherit",
    env: { ...process.env, ...(opts.env ?? {}) },
  });
  return { code: r.status ?? (r.error ? 127 : 1), out: (r.stdout ?? "") + (r.stderr ?? "") };
};

// ── Locate a Python 3 interpreter ───────────────────────────────────────────
// Accept any Python 3.x (3.11, 3.12, 3.13, 3.14…) since all pinned deps
// support 3.11+. On Windows, prefer py launcher versions first.
const pyCandidates = isWin
  ? [
      ["py", "-3.12"],
      ["py", "-3.11"],
      ["py", "-3"],
      ["python3.12"],
      ["python3.11"],
      ["python"],
    ]
  : [
      ["python3.12"],
      ["python3.11"],
      ["python3"],
      ["python"],
    ];

let pyCmd = null;
for (const c of pyCandidates) {
  const r = run(c[0], [...c.slice(1), "--version"], { stdio: "pipe" });
  if (r.code === 0 && /Python 3\.\d+/.test(r.out)) {
    pyCmd = c;
    break;
  }
}
if (!pyCmd) {
  console.error("ERROR: No Python 3 interpreter found. Install Python 3.11+ first.");
  process.exit(1);
}
console.log(`Using Python: ${pyCmd.join(" ")}`);

// ── Create venv ─────────────────────────────────────────────────────────────
if (recreate && fs.existsSync(venvDir)) {
  console.log("Removing existing .venv-verify (--recreate)…");
  fs.rmSync(venvDir, { recursive: true, force: true });
}

if (!fs.existsSync(venvDir)) {
  console.log("Creating .venv-verify…");
  // --without-pip avoids py launcher shell-resolution issues on Windows;
  // pip is bootstrapped below via ensurepip using the venv python directly.
  const r = run(pyCmd[0], [...pyCmd.slice(1), "-m", "venv", "--without-pip", venvDir]);
  if (r.code !== 0) {
    console.error("Failed to create venv.");
    process.exit(1);
  }
}

const venvPy = isWin
  ? path.join(venvDir, "Scripts", "python.exe")
  : path.join(venvDir, "bin", "python");

// Bootstrap pip if the venv was created without it (common with py launcher)
const pipCheck = run(venvPy, ["-m", "pip", "--version"], { stdio: "pipe" });
if (pipCheck.code !== 0) {
  console.log("Bootstrapping pip via ensurepip…");
  const ep = run(venvPy, ["-m", "ensurepip", "--upgrade"]);
  if (ep.code !== 0) {
    console.error("ensurepip failed; cannot install dependencies.");
    process.exit(1);
  }
}

// ── Dependency lists (mirrored from .github/workflows/ci.yml) ───────────────
// Environment markers skip packages that don't build on Windows.
const OPENAPI_DEPS = [
  "fastapi>=0.109,<0.140",
  "pydantic>=2.5,<3",
  "pydantic-settings>=2.1,<3",
  "pyyaml",
  "structlog>=24.1,<27",
];

const API_DEPS = [
  ...OPENAPI_DEPS,
  "pydantic[email]",
  "sqlalchemy[asyncio]>=2.0,<3",
  "asyncpg",
  "aiosqlite",
  "python-jose[cryptography]",
  "passlib[bcrypt]",
  "tenacity",
  "prometheus-client",
  "opentelemetry-sdk",
  "opentelemetry-api",
  "opentelemetry-exporter-otlp-proto-grpc; sys_platform != 'win32'",
  "opentelemetry-instrumentation-fastapi",
  "strawberry-graphql[fastapi]",
  "neo4j",
  "redis>=5.0,<6",
  "celery",
  "httpx>=0.27,<0.29",
  "aiofiles",
  "email-validator",
  "PyJWT",
  "sqlglot>=23,<27",
  "croniter>=2.0,<7.0",
  "apscheduler",
  "markdown",
  "pytest>=7.4,<9",
  "pytest-asyncio>=0.23,<2",
];

const AGENTS_DEPS = [
  "langchain-core",
  "langchain-openai",
  "langgraph",
  "jsonschema",
  "respx>=0.21,<0.23",
  "click; sys_platform != 'win32'",
];

const ALL_DEPS = [...new Set([...API_DEPS, ...AGENTS_DEPS])];

// ── Install ─────────────────────────────────────────────────────────────────
console.log("Installing dependencies into .venv-verify…");
const installArgs = ["-m", "pip", "install", "--quiet", ...ALL_DEPS];
const r = run(venvPy, installArgs);
if (r.code !== 0) {
  console.error("pip install failed. See output above.");
  process.exit(1);
}
console.log("Dependencies installed successfully.");

// ── Smoke-check: OpenAPI imports for api and agents ─────────────────────────
console.log("\nRunning OpenAPI smoke checks…");
const smokeScript = `
import os, sys
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("SECRET_KEY", "ci-dummy-secret-key-at-least-32bytes!")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

svc = sys.argv[1]
if svc == "api":
    sys.path.insert(0, os.path.join(os.getcwd(), "services", "api"))
    from app.main import app
    paths = list(app.openapi().get("paths", {}).keys())
    print(f"api: {len(paths)} paths")
elif svc == "agents":
    sys.path.insert(0, os.path.join(os.getcwd(), "services", "agents"))
    from app.main import app
    paths = list(app.openapi().get("paths", {}).keys())
    print(f"agents: {len(paths)} paths")
else:
    print(f"unknown service: {svc}", file=sys.stderr)
    sys.exit(1)
`;

let allOk = true;
for (const svc of ["api", "agents"]) {
  const r = run(venvPy, ["-c", smokeScript, svc]);
  if (r.code !== 0) {
    console.error(`OpenAPI smoke FAILED for ${svc}`);
    allOk = false;
  }
}

if (!allOk) {
  console.error("\n❌ One or more smoke checks failed. See errors above.");
  process.exit(1);
}

// ── Final check: run api and agents pytest suites quietly ────────────────────
console.log("\nRunning pytest suites as final verification…");
const pytestServices = [
  { name: "api", cwd: path.join(root, "services", "api") },
  { name: "agents", cwd: path.join(root, "services", "agents") },
];
let pytestOk = true;
for (const svc of pytestServices) {
  console.log(`  ▸ ${svc.name} tests…`);
  const r = run(venvPy, ["-m", "pytest", "-q", "--tb=no"], {
    cwd: svc.cwd,
    stdio: "pipe",
  });
  if (r.code !== 0) {
    console.error(`❌ pytest (${svc.name}) FAILED (exit ${r.code})`);
    // Print last few lines so the user can diagnose without re-running
    const tail = r.out.trim().split("\n").slice(-5).join("\n");
    console.error(tail);
    pytestOk = false;
  } else {
    // Extract the summary line (e.g. "42 passed, 1 skipped")
    const summary = r.out.trim().split("\n").pop() ?? "ok";
    console.log(`  ✅ ${svc.name}: ${summary}`);
  }
}

if (!pytestOk) {
  console.error("\n❌ One or more pytest suites failed. Fix the failures before proceeding.");
  process.exit(1);
}

console.log("\n✅ .venv-verify is fully verified: OpenAPI imports + pytest suites pass.");