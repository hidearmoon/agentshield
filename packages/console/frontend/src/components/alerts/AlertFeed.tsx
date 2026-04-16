import { clsx } from "clsx";
import type { Alert } from "@/api/alerts";

interface AlertFeedProps {
  alerts: Alert[];
  loading?: boolean;
  onSelect: (alert: Alert) => void;
  selectedId?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "border-l-status-danger bg-status-danger/5",
  high: "border-l-status-warning bg-status-warning/5",
  medium: "border-l-status-info bg-status-info/5",
  low: "border-l-gray-600",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "badge-danger",
  high: "badge-warning",
  medium: "badge-info",
  low: "badge-neutral",
};

function formatAge(iso: string | null): string {
  if (!iso) return "-";
  const ms = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function AlertFeed({
  alerts,
  loading,
  onSelect,
  selectedId,
}: AlertFeedProps) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="h-20 rounded-lg bg-surface-raised animate-pulse"
          />
        ))}
      </div>
    );
  }

  if (alerts.length === 0) {
    return (
      <div className="card py-12 text-center text-sm text-gray-500">
        No alerts match the current filters
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {alerts.map((alert) => (
        <button
          key={alert.id}
          onClick={() => onSelect(alert)}
          className={clsx(
            "w-full text-left rounded-lg border-l-4 px-4 py-3 transition-colors",
            SEVERITY_COLORS[alert.severity] || "border-l-gray-700",
            selectedId === alert.id
              ? "ring-1 ring-accent/30"
              : "hover:bg-surface-raised"
          )}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-gray-200 truncate">
                {alert.title}
              </div>
              {alert.description && (
                <div className="text-xs text-gray-400 mt-0.5 truncate">
                  {alert.description}
                </div>
              )}
              <div className="flex items-center gap-2 mt-1.5">
                <span
                  className={`badge ${SEVERITY_BADGE[alert.severity] || "badge-neutral"}`}
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
                {alert.agent_id && (
                  <span className="text-xs text-gray-500">
                    {alert.agent_id}
                  </span>
                )}
              </div>
            </div>
            <span className="text-xs text-gray-500 whitespace-nowrap flex-shrink-0">
              {formatAge(alert.created_at)}
            </span>
          </div>
        </button>
      ))}
    </div>
  );
}
