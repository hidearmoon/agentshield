import type { RiskEntry } from "@/api/dashboard";
import { clsx } from "clsx";

interface RiskRankingProps {
  data: RiskEntry[];
  loading?: boolean;
}

function riskLevel(entry: RiskEntry): "high" | "medium" | "low" {
  if (entry.avg_drift > 0.7 || entry.blocked > 10) return "high";
  if (entry.avg_drift > 0.4 || entry.blocked > 3) return "medium";
  return "low";
}

export function RiskRanking({ data, loading }: RiskRankingProps) {
  return (
    <div className="card">
      <div className="card-header">Risk Ranking by Agent</div>
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-10 bg-surface-raised rounded animate-pulse" />
          ))}
        </div>
      ) : data.length === 0 ? (
        <div className="py-8 text-center text-sm text-gray-500">
          No agent activity in the selected time range
        </div>
      ) : (
        <div className="space-y-2">
          {data.map((entry, i) => {
            const level = riskLevel(entry);
            return (
              <div
                key={entry.agent_id}
                className="flex items-center gap-3 rounded-lg bg-surface-raised px-3 py-2.5"
              >
                <span className="text-xs font-mono text-gray-500 w-5">
                  {i + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-200 truncate">
                    {entry.agent_id}
                  </div>
                  <div className="text-xs text-gray-500">
                    {entry.total_calls.toLocaleString()} calls
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-gray-400">
                    {entry.blocked} blocked
                  </div>
                  <div className="text-xs text-gray-500">
                    drift: {entry.avg_drift.toFixed(3)}
                  </div>
                </div>
                <span
                  className={clsx(
                    "badge",
                    level === "high" && "badge-danger",
                    level === "medium" && "badge-warning",
                    level === "low" && "badge-success"
                  )}
                >
                  {level}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
