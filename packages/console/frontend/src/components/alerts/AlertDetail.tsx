import { Link } from "react-router-dom";
import { clsx } from "clsx";
import type { Alert } from "@/api/alerts";

interface AlertDetailProps {
  alert: Alert;
  onAcknowledge: () => void;
  onResolve: () => void;
  acknowledging?: boolean;
  resolving?: boolean;
}

export function AlertDetail({
  alert,
  onAcknowledge,
  onResolve,
  acknowledging,
  resolving,
}: AlertDetailProps) {
  return (
    <div className="card">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-100">
            {alert.title}
          </h3>
          <div className="flex items-center gap-2 mt-1">
            <span
              className={clsx(
                "badge",
                alert.severity === "critical"
                  ? "badge-danger"
                  : alert.severity === "high"
                    ? "badge-warning"
                    : alert.severity === "medium"
                      ? "badge-info"
                      : "badge-neutral"
              )}
            >
              {alert.severity}
            </span>
            <span
              className={clsx(
                "badge",
                alert.status === "open"
                  ? "badge-danger"
                  : alert.status === "acknowledged"
                    ? "badge-warning"
                    : "badge-success"
              )}
            >
              {alert.status}
            </span>
          </div>
        </div>

        <div className="flex gap-2">
          {alert.status === "open" && (
            <button
              onClick={onAcknowledge}
              disabled={acknowledging}
              className="btn-secondary text-sm"
            >
              {acknowledging ? "..." : "Acknowledge"}
            </button>
          )}
          {alert.status !== "resolved" && (
            <button
              onClick={onResolve}
              disabled={resolving}
              className="btn-primary text-sm"
            >
              {resolving ? "..." : "Resolve"}
            </button>
          )}
        </div>
      </div>

      {alert.description && (
        <p className="text-sm text-gray-300 mb-4">{alert.description}</p>
      )}

      <dl className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <dt className="text-xs text-gray-500 uppercase">Agent</dt>
          <dd className="text-gray-200 mt-0.5">{alert.agent_id || "-"}</dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase">Trace</dt>
          <dd className="mt-0.5">
            {alert.trace_id ? (
              <Link
                to={`/traces/${alert.trace_id}`}
                className="text-accent hover:text-accent-hover text-xs font-mono"
              >
                {alert.trace_id.slice(0, 16)}...
              </Link>
            ) : (
              <span className="text-gray-400">-</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase">Created</dt>
          <dd className="text-gray-200 mt-0.5">
            {alert.created_at
              ? new Date(alert.created_at).toLocaleString()
              : "-"}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-gray-500 uppercase">Acknowledged</dt>
          <dd className="text-gray-200 mt-0.5">
            {alert.acknowledged_at
              ? new Date(alert.acknowledged_at).toLocaleString()
              : "-"}
          </dd>
        </div>
      </dl>

      {alert.metadata && Object.keys(alert.metadata).length > 0 && (
        <div className="mt-4">
          <h4 className="text-xs text-gray-500 uppercase mb-2">Metadata</h4>
          <pre className="rounded-lg bg-surface-raised p-3 text-xs text-gray-300 font-mono overflow-x-auto">
            {JSON.stringify(alert.metadata, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
