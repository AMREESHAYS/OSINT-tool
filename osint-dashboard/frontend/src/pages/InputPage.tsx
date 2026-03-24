import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { analyzeQuery } from '../services/api';

function InputPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await analyzeQuery(query);
      navigate(`/results/${response.request_id}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unexpected error occurred.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10">
      <div className="cyber-card w-full p-8">
        <p className="mb-2 text-sm uppercase tracking-[0.2em] text-cyber-muted">OSINT Intelligence Dashboard</p>
        <h1 className="mb-6 text-3xl font-bold text-cyan-100">Target Input Analyzer</h1>

        <form className="space-y-4" onSubmit={handleSubmit}>
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Enter email, domain, or username"
            className="w-full rounded-lg border border-cyan-900/60 bg-cyber-panelAlt px-4 py-3 text-slate-100 outline-none ring-cyan-500 focus:ring"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="rounded-lg bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {loading ? 'Analyzing...' : 'Run OSINT Scan'}
          </button>
        </form>

        {error ? <p className="mt-4 text-sm text-rose-400">{error}</p> : null}
      </div>
    </main>
  );
}

export default InputPage;
