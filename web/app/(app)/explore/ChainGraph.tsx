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
 * The chain drawn left to right in labelled columns ("stages"):
 *   VULNERABILITY | WEAKNESS | PARENT +1 | PARENT +2 | ATTACK PATTERN | ATT&CK TECHNIQUE
 * Each stage is a dagre rank: edge `minlen` pushes every attack pattern past
 * the last weakness column, so a column never mixes types and no edge needs
 * a text label (the column headers say what each hop is).
 * Node TYPE is also shown by SHAPE (HANDOFF 4.10): CVE square, CWE diamond,
 * CAPEC hexagon, Technique circle. Colour: CVE severity bar, hazard for the
 * highlighted chains.
 * Motion: columns appear hop by hop and edges draw in (DrawSVG); a click
 * skips it; reduced motion shows everything at once.
 */
const W = 248;
const H = 60;

const SEV_BAR: Record<string, string> = {
  CRITICAL: "bg-sev-critical",
  HIGH: "bg-sev-high",
  MEDIUM: "bg-sev-medium",
  LOW: "bg-sev-low",
};

function Glyph({ type }: { type: NodeType }) {
  const stroke = "var(--color-paper-dim)";
  return (
    <svg width="16" height="16" viewBox="0 0 14 14" aria-hidden="true" className="shrink-0">
      {type === "CVE" && <rect x="1.5" y="1.5" width="11" height="11" fill="none" stroke={stroke} />}
      {type === "CWE" && <path d="M7 1 13 7 7 13 1 7z" fill="none" stroke={stroke} />}
      {type === "CAPEC" && <path d="M7 1l5.2 3v6L7 13 1.8 10V4z" fill="none" stroke={stroke} />}
      {type === "Technique" && <circle cx="7" cy="7" r="5.5" fill="none" stroke={stroke} />}
    </svg>
  );
}

type ChainData = { node: GraphNode; hot: boolean; dim: boolean; selected: boolean };
type HeaderData = { text: string };

function ChainNode({ data }: NodeProps<Node<ChainData>>) {
  const { node, hot, dim, selected } = data;
  const sev = node.type === "CVE" ? SEV_BAR[String(node.props.severity)] : undefined;
  return (
    <div
      style={{ width: W, height: H }}
      className={`relative flex cursor-pointer items-center gap-2.5 border bg-ink-2 px-3 text-left transition-colors duration-150 hover:border-rule-strong ${
        selected ? "border-hazard" : hot ? "border-hazard/70" : "border-rule"
      } ${dim ? "opacity-30" : ""}`}
    >
      {sev ? <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-1 ${sev}`} /> : null}
      <Handle type="target" position={Position.Left} />
      <Glyph type={node.type} />
      <span className="min-w-0">
        <span className={`tl-mono block text-[13px] leading-5 ${hot || selected ? "text-hazard" : "text-paper"}`}>{node.id}</span>
        <span className="block truncate text-[12px] leading-5 text-paper-dim" title={node.label}>
          {node.type === "CVE" ? (node.props.severity ? String(node.props.severity) : "Unscored") : node.label}
        </span>
      </span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

function ColumnHeader({ data }: NodeProps<Node<HeaderData>>) {
  return (
    <div style={{ width: W }} className="tl-label border-b border-rule pb-1.5 text-[11px] text-paper-faint">
      {data.text}
    </div>
  );
}

const nodeTypes = { chain: ChainNode, header: ColumnHeader };

/** Stage of each node: hops from the CVE over INSTANCE_OF / CHILD_OF (weaknesses), then fixed stages for CAPEC and technique. */
function stages(chain: Chain) {
  const st = new Map<string, number>([[chain.meta.cve, 0]]);
  const cweEdges = chain.edges.filter((e) => e.type === "INSTANCE_OF" || e.type === "CHILD_OF");
  for (let changed = true; changed; ) {
    changed = false;
    for (const e of cweEdges) {
      const s = st.get(e.source);
      if (s !== undefined && (st.get(e.target) ?? Infinity) > s + 1) {
        st.set(e.target, s + 1);
        changed = true;
      }
    }
  }
  const lastCwe = Math.max(1, ...chain.nodes.filter((n) => n.type === "CWE").map((n) => st.get(n.id) ?? 1));
  for (const n of chain.nodes) {
    if (n.type === "CAPEC") st.set(n.id, lastCwe + 1);
    if (n.type === "Technique") st.set(n.id, lastCwe + 2);
  }
  return { st, lastCwe };
}

function stageLabel(stage: number, lastCwe: number): string {
  if (stage === 0) return "Vulnerability";
  if (stage === 1) return "Weakness";
  if (stage <= lastCwe) return `Parent weakness +${stage - 1}`;
  if (stage === lastCwe + 1) return "Attack pattern";
  return "ATT&CK technique";
}

/** Edges in chain order (EXPLOITS is stored CAPEC->CWE; it is drawn CWE->CAPEC). */
function flowEdges(chain: Chain) {
  return chain.edges.map((e) =>
    e.type === "EXPLOITS"
      ? { id: `${e.target}>${e.source}`, from: e.target, to: e.source }
      : { id: `${e.source}>${e.target}`, from: e.source, to: e.target },
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

  const layout = useMemo(() => {
    const { st, lastCwe } = stages(chain);
    const edges = flowEdges(chain);
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 18, ranksep: 96, marginx: 8, marginy: 8 });
    g.setDefaultEdgeLabel(() => ({}));
    chain.nodes.forEach((n) => g.setNode(n.id, { width: W, height: H }));
    // minlen = stage gap, so each stage is exactly one dagre rank (one column).
    edges.forEach((e) => g.setEdge(e.from, e.to, { minlen: Math.max(1, (st.get(e.to) ?? 1) - (st.get(e.from) ?? 0)) }));
    dagre.layout(g);

    // One header per occupied stage, placed above that column.
    const top = Math.min(...chain.nodes.map((n) => g.node(n.id).y)) - H / 2 - 44;
    const xs = new Map<number, number>();
    chain.nodes.forEach((n) => xs.set(st.get(n.id) ?? 0, g.node(n.id).x));
    const headers = [...xs].map(([stage, x]) => ({ stage, x, text: stageLabel(stage, lastCwe) }));
    return { g, edges, st, headers, top };
  }, [chain]);

  const hotSet = useMemo(() => {
    if (!selected) return null;
    const on = chain.paths.filter((p) => p.includes(selected));
    const nodes = new Set(on.flat());
    const edges = new Set<string>();
    for (const p of on) for (let i = 0; i < p.length - 1; i++) edges.add(`${p[i]}>${p[i + 1]}`);
    if (selected === chain.meta.cve) chain.nodes.forEach((n) => n.type === "CWE" && layout.st.get(n.id) === 1 && nodes.add(n.id));
    nodes.add(selected);
    return { nodes, edges };
  }, [chain, selected, layout]);

  const nodes: Node[] = [
    ...layout.headers.map((h) => ({
      id: `header-${h.stage}`,
      type: "header",
      position: { x: h.x - W / 2, y: layout.top },
      className: `tl-rank-${h.stage}`,
      data: { text: h.text },
      draggable: false,
      selectable: false,
    })),
    ...chain.nodes.map((n) => {
      const pos = layout.g.node(n.id);
      return {
        id: n.id,
        type: "chain",
        position: { x: pos.x - W / 2, y: pos.y - H / 2 },
        className: `tl-rank-${layout.st.get(n.id) ?? 9}`,
        data: {
          node: n,
          selected: selected === n.id,
          hot: !!hotSet?.nodes.has(n.id),
          dim: !!hotSet && !hotSet.nodes.has(n.id),
        },
        draggable: false,
      };
    }),
  ];

  const edges: Edge[] = layout.edges.map((e) => {
    const hot = !!hotSet && (hotSet.edges.has(e.id) || (selected === chain.meta.cve && e.from === selected));
    return {
      id: e.id,
      source: e.from,
      target: e.to,
      type: "default",
      className: `tl-rank-${layout.st.get(e.from) ?? 9} ${hot ? "tl-hot" : hotSet ? "tl-dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: hot ? "var(--color-hazard)" : "var(--color-rule-strong)" },
    };
  });

  useGSAP(
    () => {
      const root = wrap.current;
      if (!root) return;
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const max = Math.max(...layout.st.values(), 0);
        const t = gsap.timeline({ defaults: { ease: "power2.out" } });
        for (let r = 0; r <= max; r++) {
          const ns = root.querySelectorAll(`.react-flow__node.tl-rank-${r}`);
          const es = root.querySelectorAll(`.react-flow__edge.tl-rank-${r} .react-flow__edge-path`);
          if (ns.length) t.from(ns, { autoAlpha: 0, x: -10, duration: 0.25, stagger: 0.015 });
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
      className="tl-flow h-[38rem] w-full border border-rule bg-ink"
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
        fitViewOptions={{ padding: 0.06, maxZoom: 1.25 }}
        minZoom={0.15}
        maxZoom={2}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable={false}
        onNodeClick={(_, n) => (n.type === "header" ? null : onSelect(n.id === selected ? null : n.id))}
        onPaneClick={() => onSelect(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--color-rule)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
