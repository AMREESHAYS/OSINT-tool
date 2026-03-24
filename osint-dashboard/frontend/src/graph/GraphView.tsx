import ForceGraph2D from 'react-force-graph-2d';

import type { GraphEdge, GraphNode } from '../types/osint';

type GraphViewProps = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

function GraphView({ nodes, edges }: GraphViewProps) {
  return (
    <div className="cyber-card h-[420px] overflow-hidden p-2">
      <ForceGraph2D
        graphData={{ nodes, links: edges }}
        nodeLabel={(node) => `${node.id} (${node.type})`}
        linkDirectionalParticles={1}
        linkDirectionalParticleSpeed={0.004}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const n = node as GraphNode;
          const label = n.id;
          const fontSize = 12 / globalScale;
          ctx.font = `${fontSize}px Sans-Serif`;
          ctx.fillStyle = '#00ffa6';
          ctx.beginPath();
          ctx.arc(node.x ?? 0, node.y ?? 0, 5, 0, 2 * Math.PI, false);
          ctx.fill();
          ctx.fillStyle = '#dbeafe';
          ctx.fillText(label, (node.x ?? 0) + 8, (node.y ?? 0) + 4);
        }}
      />
    </div>
  );
}

export default GraphView;
