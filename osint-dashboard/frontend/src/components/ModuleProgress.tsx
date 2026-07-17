import type { ModuleResult } from '../types/osint';

export type ModuleState = { status: 'running' | 'done'; result?: ModuleResult };

function ModuleProgress({ states }: { states: Record<string, ModuleState> }) {
  const entries = Object.entries(states);
  return (
    <div className="cyber-card p-4">
      <h2 className="mb-3 text-lg font-semibold text-cyan-100">Modules</h2>
      {entries.length === 0 ? (
        <p className="text-cyber-muted text-sm">Waiting for scan to start…</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {entries.map(([name, s]) => (
            <li key={name} className="flex items-center justify-between">
              <span className="text-slate-200">{name}</span>
              <span
                className={
                  s.status === 'done'
                    ? s.result?.ok
                      ? 'text-emerald-400'
                      : 'text-rose-400'
                    : 'text-cyan-300'
                }
              >
                {s.status === 'running'
                  ? 'running…'
                  : s.result?.ok
                    ? `✓ ${s.result.findings.length}`
                    : `✗ ${s.result?.error ?? 'failed'}`}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default ModuleProgress;
