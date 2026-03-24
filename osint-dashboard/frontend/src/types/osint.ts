export type AnalyzeResponse = {
  request_id: string;
  normalized_query: string;
  input_type: 'email' | 'domain' | 'username';
  message: string;
  next_steps: string[];
};

export type Breach = {
  name: string;
  date: string;
  data_exposed: string[];
};

export type Profile = {
  platform: string;
  url: string;
  found: boolean;
};

export type GraphNode = {
  id: string;
  type: string;
};

export type GraphEdge = {
  source: string;
  target: string;
};

export type StoredResult = {
  request_id: string;
  query: string;
  input_type: 'email' | 'domain' | 'username';
  status: string;
  details?: {
    summary?: string;
    domain_intelligence?: {
      dns?: {
        a?: string[];
        mx?: string[];
        txt?: string[];
        errors?: Record<string, string>;
      };
    };
    email_intelligence?: {
      breaches?: Breach[];
    };
    username_intelligence?: {
      profiles?: Profile[];
    };
    graph?: {
      nodes: GraphNode[];
      edges: GraphEdge[];
    };
  };
};
