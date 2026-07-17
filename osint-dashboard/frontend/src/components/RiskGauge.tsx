import type { Severity } from '../types/osint';

const COLORS: Record<Severity, string> = {
  INFO: '#8ea0c9',
  LOW: '#3b82f6',
  MEDIUM: '#eab308',
  HIGH: '#ef4444',
  CRITICAL: '#d946ef',
};

function RiskGauge({ level, score }: { level: Severity; score: number }) {
  return (
    <div className="cyber-card flex flex-col items-center justify-center p-6">
      <p className="text-xs uppercase tracking-[0.2em] text-cyber-muted">Risk</p>
      <p className="text-4xl font-bold" style={{ color: COLORS[level] }}>{level}</p>
      <p className="text-sm text-slate-300">score {score}</p>
    </div>
  );
}

export default RiskGauge;
