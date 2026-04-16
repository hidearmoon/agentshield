import type { Span } from "@/api/traces";
import { IntentDriftBadge } from "./IntentDriftBadge";

interface SpanDetailProps {
  span: Span;
  onClose: () => void;
}

function Field({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div>
      <dt className="text-xs font-medium text-gray-500 uppercase tracking-wider">
        {label}
      </dt>
      <dd className="mt-1 text-sm text-gray-200 break-all font-mono">
        {value ?? "-"}
      </dd>
    </div>
  );
}

export function SpanDetail({ span, onClose }: SpanDetailProps) {
  const decisionClass =
    span.decision === "BLOCK"
      ? "badge-danger"
      : span.decision === "ALLOW"
        ? "badge-success"
        : span.decision === "REQUIRE_CONFIRMATION"
          ? "badge-warning"
          : "badge-neutral";

  return (
    <div className="card mt-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200">Span Detail</h3>
        <button
          onClick={onClose}
          className="btn-ghost p-1"
          aria-label="Close"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <dl className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <Field label="Span ID" value={span.span_id} />
        <Field label="Parent Span" value={span.parent_span_id || "(root)"} />
        <Field label="Agent" value={span.agent_id} />
        <Field label="Type" value={span.span_type} />
        <Field label="Tool" value={span.tool_name} />
        <div>
          <dt className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            Decision
          </dt>
          <dd className="mt-1">
            <span className={`badge ${decisionClass}`}>{span.decision}</span>
          </dd>
        </div>
        <Field label="Decision Engine" value={span.decision_engine} />
        <div>
          <dt className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            Intent Drift
          </dt>
          <dd className="mt-1">
            <IntentDriftBadge score={span.intent_drift_score} />
          </dd>
        </div>
        <Field label="Data Trust" value={span.data_trust_level} />
        <Field label="Start" value={span.start_time} />
        <Field label="End" value={span.end_time} />
        <Field label="Merkle Hash" value={span.merkle_hash} />
      </dl>

      {span.intent && (
        <div className="mt-4">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
            Intent
          </h4>
          <div className="rounded-lg bg-surface-raised p-3 text-sm text-gray-300 font-mono">
            {span.intent}
          </div>
        </div>
      )}

      {span.decision_reason && (
        <div className="mt-4">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
            Decision Reason
          </h4>
          <div className="rounded-lg bg-surface-raised p-3 text-sm text-gray-300">
            {span.decision_reason}
          </div>
        </div>
      )}

      {span.tool_params && (
        <div className="mt-4">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
            Tool Parameters
          </h4>
          <pre className="rounded-lg bg-surface-raised p-3 text-xs text-gray-300 font-mono overflow-x-auto">
            {span.tool_params}
          </pre>
        </div>
      )}

      {span.tool_result_summary && (
        <div className="mt-4">
          <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
            Tool Result Summary
          </h4>
          <div className="rounded-lg bg-surface-raised p-3 text-sm text-gray-300">
            {span.tool_result_summary}
          </div>
        </div>
      )}
    </div>
  );
}
