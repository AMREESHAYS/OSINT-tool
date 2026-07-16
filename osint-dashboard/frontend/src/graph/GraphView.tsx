import { useEffect, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

import type { GraphEdge, GraphNode } from '../types/osint';

type GraphViewProps = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

const NODE_COLORS: Record<string, string> = {
  target: '#00ffa6',
  ip: '#38bdf8',
  subdomain: '#a78bfa',
  tech: '#f472b6',
  port: '#f59e0b',
  endpoint: '#facc15',
  profile: '#34d399',
};

function GraphView({ nodes, edges }: GraphViewProps) {
  // react-force-graph-2d collapses to 0 height when it measures its own block
  // wrapper instead of the sized card, so measure the container and pass explicit dims.
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return undefined;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={containerRef} className="cyber-card h-[420px] overflow-hidden p-2">
      <ForceGraph2D
        width={size.width}
        height={size.height}
        graphData={{ nodes, links: edges }}
        nodeLabel={(node) => `${node.id} (${node.type})`}
        linkDirectionalParticles={1}
        linkDirectionalParticleSpeed={0.004}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const n = node as GraphNode;
          const label = n.id;
          const fontSize = 12 / globalScale;
          ctx.font = `${fontSize}px Sans-Serif`;
          ctx.fillStyle = NODE_COLORS[n.type] ?? '#00ffa6';
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
