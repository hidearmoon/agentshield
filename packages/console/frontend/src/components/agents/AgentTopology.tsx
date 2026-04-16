import { useEffect, useRef, useMemo } from "react";
import type { Topology } from "@/api/agents";

interface AgentTopologyProps {
  topology: Topology;
}

interface LayoutNode {
  id: string;
  name: string;
  x: number;
  y: number;
  tools: string[];
}

export function AgentTopology({ topology }: AgentTopologyProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Compute a simple circular layout
  const layout = useMemo<LayoutNode[]>(() => {
    const { nodes } = topology;
    if (nodes.length === 0) return [];
    const cx = 400;
    const cy = 250;
    const radius = Math.min(180, 40 * nodes.length);
    return nodes.map((n, i) => {
      const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
      return {
        id: n.id,
        name: n.name,
        tools: n.tools,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });
  }, [topology]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = 800 * dpr;
    canvas.height = 500 * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, 800, 500);

    const nodeMap = new Map(layout.map((n) => [n.id, n]));

    // Draw edges
    for (const edge of topology.edges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) continue;

      const lineWidth = Math.min(4, Math.max(1, Math.log2(edge.weight + 1)));
      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = `rgba(99, 102, 241, ${Math.min(0.8, 0.2 + edge.weight / 50)})`;
      ctx.lineWidth = lineWidth;
      ctx.stroke();

      // Arrow head
      const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
      const headLen = 10;
      const arrowX = tgt.x - 20 * Math.cos(angle);
      const arrowY = tgt.y - 20 * Math.sin(angle);
      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(
        arrowX - headLen * Math.cos(angle - Math.PI / 6),
        arrowY - headLen * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        arrowX - headLen * Math.cos(angle + Math.PI / 6),
        arrowY - headLen * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fillStyle = "rgba(99, 102, 241, 0.6)";
      ctx.fill();
    }

    // Draw nodes
    for (const node of layout) {
      // Circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, 16, 0, Math.PI * 2);
      ctx.fillStyle = "#1c2030";
      ctx.fill();
      ctx.strokeStyle = "#6366f1";
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label
      ctx.font = "12px Inter, sans-serif";
      ctx.fillStyle = "#e5e7eb";
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.fillText(node.name, node.x, node.y + 22);

      // Tool count
      if (node.tools.length > 0) {
        ctx.font = "10px Inter, sans-serif";
        ctx.fillStyle = "#9ca3af";
        ctx.fillText(
          `${node.tools.length} tool${node.tools.length !== 1 ? "s" : ""}`,
          node.x,
          node.y + 37
        );
      }
    }
  }, [layout, topology.edges]);

  if (topology.nodes.length === 0) {
    return (
      <div className="card py-16 text-center text-sm text-gray-500">
        No agents to display in the topology
      </div>
    );
  }

  return (
    <div className="card p-0 overflow-hidden">
      <div className="card-header px-5 pt-5">Agent Communication Topology</div>
      <canvas
        ref={canvasRef}
        width={800}
        height={500}
        style={{ width: "100%", height: "auto" }}
      />
    </div>
  );
}
