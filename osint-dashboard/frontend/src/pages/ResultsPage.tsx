import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import ModuleProgress, { ModuleState } from '../components/ModuleProgress';
import RiskGauge from '../components/RiskGauge';
import SectionCard from '../components/SectionCard';
import GraphView from '../graph/GraphView';
import { openScanStream } from '../services/api';
import type { Finding, ReportPayload, Severity } from '../types/osint';

const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_COLOR: Record<Severity, string> = {
  INFO: 'text-slate-400',
  LOW: 'text-blue-400',
  MEDIUM: 'text-yellow-400',
  HIGH: 'text-red-400',
  CRITICAL: 'text-fuchsia-400',
};

function ResultsPage() {
  const [params] = useSearchParams();
  const target = params.get('target') ?? '';
  const [states, setStates] = useState<Record<string, ModuleState>>({});
  const [payload, setPayload] = useState<ReportPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!target) return undefined;
    setStates({});
    setPayload(null);
    setError(null);
    const es = openScanStream(target, {
      onModuleStarted: (m) => setStates((s) => ({ ...s, [m]: { status: 'running' } })),
      onModuleFinished: (r) => setStates((s) => ({ ...s, [r.module]: { status: 'done', result: r } })),
      onReport: (p) => setPayload(p),
      onError: (d) => setError(d),
    });
    return () => es.close();
  }, [target]);

  const findings: Finding[] = useMemo(
    () => Object.values(states).flatMap((s) => s.result?.findings ?? []),
    [states],
  );
  const sortedFindings = useMemo(
    () => [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    [findings],
  );
  const screenshot = findings.find((f) => f.module === 'screenshot' && typeof f.data?.image === 'string');
  const breaches = findings.filter((f) => f.module === 'breach');
  const summary = payload?.summary;

  const report = payload?.report;
  const graph = payload?.graph ?? { nodes: [], edges: [] };
  const done = payload !== null;

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-cyber-muted">Investigation</p>
          <h1 className="text-2xl font-bold text-cyan-100">{target || 'No target'}</h1>
          <p className="text-sm text-slate-300">{error ? `Error: ${error}` : done ? 'Complete' : 'Scanning…'}</p>
        </div>
        <Link to="/" className="rounded-md border border-cyan-800 px-3 py-2 text-sm text-cyan-200 hover:bg-cyan-900/30">
          New Scan
        </Link>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <ModuleProgress states={states} />
        {report ? <RiskGauge level={report.risk_level} score={report.risk_score} /> : (
          <div className="cyber-card flex items-center justify-center p-6 text-cyber-muted">Computing risk…</div>
        )}
        <SectionCard title="AI Summary">
          <p className="text-slate-200">{summary ?? (payload ? 'No summary.' : 'Analyzing…')}</p>
        </SectionCard>
      </div>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <SectionCard title="Screenshot">
          {screenshot ? (
            <img src={screenshot.data.image as string} alt="Homepage screenshot" className="max-w-full rounded-md" />
          ) : (
            <p className="text-cyber-muted">No screenshot (domain scans only; enable the screenshots extra).</p>
          )}
        </SectionCard>
        <SectionCard title="Breaches">
          {breaches.length === 0 ? (
            <p className="text-cyber-muted">No breach data (email scans with HIBP_API_KEY).</p>
          ) : (
            breaches.map((b, i) => (
              <p key={`${b.title}-${i}`} className="text-slate-200">
                <span className="text-cyber-accent">{b.title}</span> — {b.detail}
              </p>
            ))
          )}
        </SectionCard>
      </div>

      <div className="mt-6">
        <h2 className="mb-3 text-xl font-semibold text-cyan-100">Findings</h2>
        <div className="cyber-card divide-y divide-cyan-900/30 p-2">
          {sortedFindings.length === 0 ? (
            <p className="p-3 text-cyber-muted">No findings yet.</p>
          ) : (
            sortedFindings.map((f, i) => (
              <div key={`${f.module}-${f.title}-${i}`} className="p-3">
                <p>
                  <span className={`mr-2 text-xs font-bold ${SEV_COLOR[f.severity]}`}>{f.severity}</span>
                  <span className="text-slate-400">[{f.module}]</span> <span className="text-slate-100">{f.title}</span>
                </p>
                {f.detail ? <pre className="mt-1 whitespace-pre-wrap text-xs text-slate-400">{f.detail}</pre> : null}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="mt-6">
        <h2 className="mb-3 text-xl font-semibold text-cyan-100">Relationship Graph</h2>
        <GraphView nodes={graph.nodes} edges={graph.edges} />
      </div>
    </main>
  );
}

export default ResultsPage;
