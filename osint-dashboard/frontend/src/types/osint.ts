export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type Finding = {
  module: string;
  title: string;
  detail: string;
  severity: Severity;
  data: Record<string, unknown>;
};

export type ModuleResult = {
  module: string;
  ok: boolean;
  error: string | null;
  duration_ms: number;
  findings: Finding[];
};

export type ScanReport = {
  target: string;
  target_type: string;
  started_at: string;
  finished_at: string;
  modules: ModuleResult[];
  risk_score: number;
  risk_level: Severity;
};

export type GraphNode = { id: string; type: string };
export type GraphEdge = { source: string; target: string };

export type ReportPayload = {
  report: ScanReport;
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
};
