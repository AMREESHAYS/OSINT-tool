import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';

function InputPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const target = query.trim();
    if (!target) return;
    navigate(`/results?target=${encodeURIComponent(target)}`);
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-4xl items-center px-4 py-10">
      <div className="cyber-card w-full p-8">
        <p className="mb-2 text-sm uppercase tracking-[0.2em] text-cyber-muted">OSINT Recon Engine</p>
        <h1 className="mb-6 text-3xl font-bold text-cyan-100">Target Input</h1>

        <form className="space-y-4" onSubmit={handleSubmit}>
          <input
            type="text"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Enter domain, email, username, or IP"
            className="w-full rounded-lg border border-cyan-900/60 bg-cyber-panelAlt px-4 py-3 text-slate-100 outline-none ring-cyan-500 focus:ring"
            required
          />
          <button
            type="submit"
            className="rounded-lg bg-cyan-500 px-5 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400"
          >
            Run OSINT Scan
          </button>
        </form>
      </div>
    </main>
  );
}

export default InputPage;
