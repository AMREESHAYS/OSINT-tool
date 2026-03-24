import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import SectionCard from '../components/SectionCard';
import GraphView from '../graph/GraphView';
import { getResultById } from '../services/api';
import type { StoredResult } from '../types/osint';

function ResultsPage() {
  const { id = '' } = useParams();
  const [result, setResult] = useState<StoredResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadResult() {
      setLoading(true);
      setError(null);
      try {
        const data = await getResultById(id);
        if (active) setResult(data);
      } catch (err) {
        if (!active) return;
        const message = err instanceof Error ? err.message : 'Failed to load results.';
        setError(message);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadResult();
    return () => {
      active = false;
    };
  }, [id]);

  if (loading) {
    return (
      <main className="mx-auto flex min-h-screen max-w-6xl items-center justify-center px-4">
        <div className="animate-pulse text-cyan-300">Loading OSINT intelligence...</div>
      </main>
    );
  }

  if (error || !result) {
    return (
      <main className="mx-auto flex min-h-screen max-w-6xl flex-col items-center justify-center gap-4 px-4">
        <p className="text-rose-400">{error ?? 'Result not found.'}</p>
        <Link to="/" className="rounded-md bg-cyan-500 px-4 py-2 font-semibold text-slate-900">
          Back to Dashboard
        </Link>
      </main>
    );
  }

  const breaches = result.details?.email_intelligence?.breaches ?? [];
  const dns = result.details?.domain_intelligence?.dns;
  const profiles = result.details?.username_intelligence?.profiles ?? [];
  const graph = result.details?.graph ?? { nodes: [], edges: [] };
  const summary = result.details?.summary;

  return (
    <main className="mx-auto min-h-screen max-w-6xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-cyber-muted">Investigation Result</p>
          <h1 className="text-2xl font-bold text-cyan-100">{result.query}</h1>
          <p className="text-sm text-slate-300">Status: {result.status}</p>
        </div>
        <Link to="/" className="rounded-md border border-cyan-800 px-3 py-2 text-sm text-cyan-200 hover:bg-cyan-900/30">
          New Scan
        </Link>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <SectionCard title="AI Summary">
          <p className="leading-relaxed text-slate-200">
            {summary ?? 'Summary not available yet for this investigation target.'}
          </p>
        </SectionCard>

        <SectionCard title="Email Breaches">
          {breaches.length === 0 ? (
            <p className="text-cyber-muted">No breach records found for this input.</p>
          ) : (
            breaches.map((breach) => (
              <div key={`${breach.name}-${breach.date}`} className="rounded-md bg-cyber-panelAlt p-3">
                <p className="font-semibold">{breach.name}</p>
                <p className="text-xs text-cyber-muted">{breach.date}</p>
                <p className="text-xs text-slate-300">{breach.data_exposed.join(', ')}</p>
              </div>
            ))
          )}
        </SectionCard>

        <SectionCard title="Domain DNS">
          {!dns ? (
            <p className="text-cyber-muted">No DNS intelligence available for this input.</p>
          ) : (
            <>
              <p><span className="font-semibold">A:</span> {(dns.a ?? []).join(', ') || 'None'}</p>
              <p><span className="font-semibold">MX:</span> {(dns.mx ?? []).join(', ') || 'None'}</p>
              <p><span className="font-semibold">TXT:</span> {(dns.txt ?? []).join(', ') || 'None'}</p>
            </>
          )}
        </SectionCard>

        <SectionCard title="Username Profiles">
          {profiles.length === 0 ? (
            <p className="text-cyber-muted">No username footprint data for this input.</p>
          ) : (
            profiles.map((profile) => (
              <a
                key={`${profile.platform}-${profile.url}`}
                href={profile.url}
                target="_blank"
                rel="noreferrer"
                className="block rounded-md bg-cyber-panelAlt p-3 hover:bg-slate-700/50"
              >
                <p className="font-semibold">{profile.platform}</p>
                <p className="truncate text-xs text-cyan-300">{profile.url}</p>
                <p className={`text-xs ${profile.found ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {profile.found ? 'Found' : 'Not Found'}
                </p>
              </a>
            ))
          )}
        </SectionCard>
      </div>

      <div className="mt-6">
        <h2 className="mb-3 text-xl font-semibold text-cyan-100">Relationship Graph</h2>
        <GraphView nodes={graph.nodes} edges={graph.edges} />
      </div>
    </main>
  );
}

export default ResultsPage;
