import { useState } from "react";
import { clsx } from "clsx";
import type { Span } from "@/api/traces";
import { SpanDetail } from "./SpanDetail";

interface TraceTimelineProps {
  spans: Span[];
}

const SPAN_COLORS: Record<string, string> = {
  user_input: "#6366f1",
  llm_call: "#8b5cf6",
  tool_call: "#f59e0b",
  agent_call: "#3b82f6",
  data_ingest: "#22c55e",
};

const DECISION_COLORS: Record<string, string> = {
  ALLOW: "#22c55e",
  BLOCK: "#ef4444",
  REQUIRE_CONFIRMATION: "#f59e0b",
};

export function TraceTimeline({ spans }: TraceTimelineProps) {
  const [selectedSpan, setSelectedSpan] = useState<Span | null>(null);

  if (spans.length === 0) {
    return (
      <div className="card py-12 text-center text-gray-500">
        No spans in this trace
      </div>
    );
  }

  const traceStart = Math.min(
    ...spans.map((s) => new Date(s.start_time).getTime())
  );
  const traceEnd = Math.max(
    ...spans.map((s) => new Date(s.end_time).getTime())
  );
  const totalDuration = traceEnd - traceStart || 1;

  // Build depth map for parent-child nesting
  const depthMap = new Map<string, number>();
  const spanMap = new Map(spans.map((s) => [s.span_id, s]));

  function getDepth(spanId: string): number {
    if (depthMap.has(spanId)) return depthMap.get(spanId)!;
    const span = spanMap.get(spanId);
    if (!span || !span.parent_span_id || !spanMap.has(span.parent_span_id)) {
      depthMap.set(spanId, 0);
      return 0;
    }
    const d = getDepth(span.parent_span_id) + 1;
    depthMap.set(spanId, d);
    return d;
  }

  spans.forEach((s) => getDepth(s.span_id));

  return (
    <>
      <div className="card p-0 overflow-hidden">
        {/* Header */}
        <div className="flex items-center border-b border-gray-800/50 px-4 py-2">
          <div className="w-48 text-xs font-medium text-gray-500 uppercase">
            Span
          </div>
          <div className="flex-1 text-xs font-medium text-gray-500 uppercase">
            Timeline
          </div>
          <div className="w-20 text-xs font-medium text-gray-500 uppercase text-right">
            Duration
          </div>
        </div>

        {/* Spans */}
        <div className="divide-y divide-gray-800/20">
          {spans.map((span) => {
            const start = new Date(span.start_time).getTime();
            const end = new Date(span.end_time).getTime();
            const offset = ((start - traceStart) / totalDuration) * 100;
            const width = Math.max(
              ((end - start) / totalDuration) * 100,
              0.5
            );
            const depth = depthMap.get(span.span_id) || 0;
            const duration = end - start;
            const color =
              SPAN_COLORS[span.span_type] || "#6b7280";
            const decisionColor =
              DECISION_COLORS[span.decision] || "#6b7280";

            return (
              <div
                key={span.span_id}
                className={clsx(
                  "flex items-center px-4 py-2 cursor-pointer transition-colors",
                  selectedSpan?.span_id === span.span_id
                    ? "bg-surface-overlay"
                    : "hover:bg-surface-raised"
                )}
                onClick={() => setSelectedSpan(span)}
              >
                {/* Label */}
                <div
                  className="w-48 flex items-center gap-2 min-w-0"
                  style={{ paddingLeft: `${depth * 16}px` }}
                >
                  <span
                    className="h-2 w-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-xs text-gray-300 truncate">
                    {span.tool_name || span.span_type}
                  </span>
                  <span
                    className="h-1.5 w-1.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: decisionColor }}
                  />
                </div>

                {/* Bar */}
                <div className="flex-1 h-6 relative">
                  <div className="absolute inset-0 bg-surface-raised/30 rounded" />
                  <div
                    className="absolute h-full rounded opacity-80"
                    style={{
                      left: `${offset}%`,
                      width: `${width}%`,
                      backgroundColor: color,
                      minWidth: "2px",
                    }}
                  />
                </div>

                {/* Duration */}
                <div className="w-20 text-right text-xs font-mono text-gray-400">
                  {duration < 1000
                    ? `${duration}ms`
                    : `${(duration / 1000).toFixed(1)}s`}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Span detail drawer */}
      {selectedSpan && (
        <SpanDetail
          span={selectedSpan}
          onClose={() => setSelectedSpan(null)}
        />
      )}
    </>
  );
}
