"use client";

import dagre from "@dagrejs/dagre";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo, useRef } from "react";
import { gsap, MOTION_OK, useGSAP } from "@/components/motion/gsap";
import type { ChainGraph as Chain, GraphNode, NodeType } from "@/lib/graph";

/**
 * The chain drawn left to right (dagre layout), one column per hop:
 * CVE -> CWE -> parent CWEs -> CAPEC -> Technique.
 * Node TYPE is shown by SHAPE (HANDOFF 4.10): CVE square, CWE diamond,
 * CAPEC hexagon, Technique circle. Colour is reserved for severity (CVE)
 * and for the highlighted path (hazard).
 * Motion: columns appear hop by hop and edges draw in (DrawSVG); any click
 * skips to the end; reduced motion shows everything at once.
 */
const W = 196;
const H = 48;

const SEV_BAR: Record<string, string> = {
  CRITICAL: "bg-sev-critical",
  HIGH: "bg-sev-high",
  MEDIUM: "bg-sev-medium",
  LOW: "bg-sev-low",
};

function Glyph({ type }: { type: NodeType }) {
  const stroke = "var(--color-paper-dim)";
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" className="shrink-0">
      {type === "CVE" && <rect x="1.5" y="1.5" width="11" height="11" fill="none" stroke={stroke} />}
      {type === "CWE" && <path d="M7 1 13 7 7 13 1 7z" fill="none" stroke={stroke} />}
      {type === "CAPEC" && <path d="M7 1l5.2 3v6L7 13 1.8 10V4z" fill="none" stroke={stroke} />}
      {type === "Technique" && <circle cx="7" cy="7" r="5.5" fill="none" stroke={stroke} />}
    </svg>
  );
}

type FlowData = { node: GraphNode; hot: boolean; dim: boolean; selected: boolean };

function ChainNode({ data }: NodeProps<Node<FlowData>>) {
  const { node, hot, dim, selected } = data;
  const sev = node.type === "CVE" ? SEV_BAR[String(node.props.severity)] : undefined;
  return (
    <div
      className={`relative flex h-[48px] w-[196px] items-center gap-2 border bg-ink-2 px-2.5 text-left transition-colors duration-150 ${
        selected ? "border-hazard" : hot ? "border-hazard/70" : "border-rule"
      } ${dim ? "opacity-35" : ""}`}
    >
      {sev ? <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-[3px] ${sev}`} /> : null}
      <Handle type="target" position={Position.Left} />
      <Glyph type={node.type} />
      <span className="min-w-0">
        <span className={`tl-mono block text-[11px] leading-4 ${hot || selected ? "text-hazard" : "text-paper"}`}>{node.id}</span>
        <span className="block truncate text-[11px] leading-4 text-paper-dim" title={node.label}>
          {node.type === "CVE" ? (node.props.severity ? String(node.props.severity) : "Unscored") : node.label}
        </span>
      </span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { chain: ChainNode };

/** Edges for layout go in chain order (EXPLOITS is stored CAPEC->CWE; we draw it CWE->CAPEC). */
function flowEdges(chain: Chain) {
  return chain.edges.map((e) =>
    e.type === "EXPLOITS"
      ? { id: `${e.target}>${e.source}`, from: e.target, to: e.source, label: "exploited by" }
      : { id: `${e.source}>${e.target}`, from: e.source, to: e.target, label: e.type === "CHILD_OF" ? "child of" : e.type === "ENABLES" ? "enables" : "instance of" },
  );
}

export function ChainGraph({
  chain,
  selected,
  onSelect,
}: {
  chain: Chain;
  selected: string | null;
  onSelect: (id: string | null) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const tl = useRef<gsap.core.Timeline | null>(null);

  // Layout + rank (hop count from the CVE) once per chain.
  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 14, ranksep: 64, marginx: 8, marginy: 8 });
    g.setDefaultEdgeLabel(() => ({}));
    chain.nodes.forEach((n) => g.setNode(n.id, { width: W, height: H }));
    const edges = flowEdges(chain);
    edges.forEach((e) => g.setEdge(e.from, e.to));
    dagre.layout(g);
    const rank = new Map<string, number>([[chain.meta.cve, 0]]);
    for (let changed = true; changed; ) {
      changed = false;
      for (const e of edges) {
        const r = rank.get(e.from);
        if (r !== undefined && (rank.get(e.to) ?? Infinity) > r + 1) {
          rank.set(e.to, r + 1);
          changed = true;
        }
      }
    }
    return { g, edges, rank };
  }, [chain]);

  // Which nodes/edges are on a path through the selected node.
  const hotSet = useMemo(() => {
    if (!selected) return null;
    const on = chain.paths.filter((p) => p.includes(selected));
    const nodes = new Set(on.flat());
    const edges = new Set<string>();
    for (const p of on) for (let i = 0; i < p.length - 1; i++) edges.add(`${p[i]}>${p[i + 1]}`);
    if (selected === chain.meta.cve) chain.nodes.forEach((n) => n.type === "CWE" && nodes.add(n.id));
    nodes.add(selected);
    return { nodes, edges };
  }, [chain, selected]);

  const nodes: Node<FlowData>[] = chain.nodes.map((n) => {
    const pos = layout.g.node(n.id);
    return {
      id: n.id,
      type: "chain",
      position: { x: pos.x - W / 2, y: pos.y - H / 2 },
      className: `tl-rank-${layout.rank.get(n.id) ?? 9}`,
      data: {
        node: n,
        selected: selected === n.id,
        hot: !!hotSet?.nodes.has(n.id),
        dim: !!hotSet && !hotSet.nodes.has(n.id),
      },
      draggable: false,
    };
  });

  const edges: Edge[] = layout.edges.map((e) => {
    const hot = !!hotSet?.edges.has(e.id) || (!!hotSet && selected === chain.meta.cve && e.from === selected);
    return {
      id: e.id,
      source: e.from,
      target: e.to,
      label: e.label,
      type: "smoothstep",
      className: `tl-rank-${layout.rank.get(e.from) ?? 9} ${hot ? "tl-hot" : hotSet ? "tl-dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12, color: hot ? "var(--color-hazard)" : "var(--color-rule-strong)" },
    };
  });

  // Hop-by-hop reveal: column r fades in, then the edges leaving it draw.
  useGSAP(
    () => {
      const root = wrap.current;
      if (!root) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const max = Math.max(...layout.rank.values(), 0);
        const t = gsap.timeline({ defaults: { ease: "power2.out" } });
        for (let r = 0; r <= max; r++) {
          const ns = root.querySelectorAll(`.react-flow__node.tl-rank-${r}`);
          const es = root.querySelectorAll(`.react-flow__edge.tl-rank-${r} .react-flow__edge-path`);
          if (ns.length) t.from(ns, { autoAlpha: 0, x: -8, duration: 0.25, stagger: 0.015 });
          if (es.length) t.from(es, { drawSVG: "0%", duration: 0.3 }, "-=0.05");
        }
        tl.current = t;
      });
    },
    { dependencies: [chain], scope: wrap },
  );

  return (
    <div
      ref={wrap}
      className="tl-flow h-[560px] w-full border border-rule bg-ink"
      onPointerDown={() => tl.current?.progress(1)}
      aria-label={`Attack chain graph for ${chain.meta.cve}`}
      role="img"
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        colorMode="dark"
        fitView
        fitViewOptions={{ padding: 0.08 }}
        minZoom={0.2}
        maxZoom={1.6}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable={false}
        onNodeClick={(_, n) => onSelect(n.id === selected ? null : n.id)}
        onPaneClick={() => onSelect(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--color-rule)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
