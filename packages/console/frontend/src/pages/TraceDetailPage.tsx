import { useParams, Link } from "react-router-dom";
import { useTrace } from "@/hooks/useTraces";
import { TraceTimeline } from "@/components/traces/TraceTimeline";
import { IntentDriftBadge } from "@/components/traces/IntentDriftBadge";

export default function TraceDetailPage() {
  const { traceId } = useParams<{ traceId: string }>();
  const { data, isLoading, error } = useTrace(traceId ?? "");

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card py-12 text-center">
        <p className="text-status-danger mb-4">
          {error ? String(error) : "Trace not found"}
        </p>
        <Link to="/traces" className="btn-secondary">
          Back to Traces
        </Link>
      </div>
    );
  }

  const { summary, spans } = data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <Link
              to="/traces"
              className="text-gray-500 hover:text-gray-300 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5 8.25 12l7.5-7.5" />
              </svg>
            </Link>
            <h2 className="text-xl font-semibold text-gray-100">
              Trace Detail
            </h2>
          </div>
          <p className="text-sm font-mono text-gray-500 mt-1 ml-8">
            {traceId}
          </p>
        </div>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="card">
            <div className="card-header">Spans</div>
            <div className="text-2xl font-bold text-accent">
              {summary.span_count}
            </div>
          </div>
          <div className="card">
            <div className="card-header">Agents</div>
            <div className="text-sm text-gray-200">
              {summary.agents.join(", ") || "-"}
            </div>
          </div>
          <div className="card">
            <div className="card-header">Decisions</div>
            <div className="flex gap-1 mt-1">
              {summary.decisions.map((d) => {
                let cls = "badge-neutral";
                if (d === "BLOCK") cls = "badge-danger";
                else if (d === "ALLOW") cls = "badge-success";
                else if (d === "REQUIRE_CONFIRMATION") cls = "badge-warning";
                return (
                  <span key={d} className={`badge ${cls}`}>
                    {d === "REQUIRE_CONFIRMATION" ? "CONFIRM" : d}
                  </span>
                );
              })}
            </div>
          </div>
          <div className="card">
            <div className="card-header">Max Drift</div>
            <IntentDriftBadge score={summary.max_drift} />
          </div>
          <div className="card">
            <div className="card-header">Duration</div>
            <div className="text-sm text-gray-200">
              {summary.start_time && summary.end_time
                ? `${(
                    new Date(summary.end_time).getTime() -
                    new Date(summary.start_time).getTime()
                  ).toLocaleString()}ms`
                : "-"}
            </div>
          </div>
        </div>
      )}

      {/* Timeline */}
      <TraceTimeline spans={spans} />
    </div>
  );
}
