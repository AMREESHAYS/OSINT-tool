import { ReactNode } from 'react';

type SectionCardProps = {
  title: string;
  children: ReactNode;
};

function SectionCard({ title, children }: SectionCardProps) {
  return (
    <section className="cyber-card p-4 md:p-5">
      <h2 className="mb-3 text-lg font-semibold text-cyber-accent">{title}</h2>
      <div className="space-y-2 text-sm text-slate-200">{children}</div>
    </section>
  );
}

export default SectionCard;
