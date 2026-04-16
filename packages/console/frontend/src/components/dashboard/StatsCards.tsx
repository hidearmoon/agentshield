import type { DashboardSummary } from "@/api/dashboard";
import { clsx } from "clsx";

interface StatsCardsProps {
  stats: DashboardSummary | undefined;
  loading?: boolean;
}

interface StatDef {
  label: string;
  key: keyof DashboardSummary;
  format?: (v: number) => string;
  color: string;
  bgColor: string;
}

const STAT_DEFS: StatDef[] = [
  {
    label: "Total Calls",
    key: "total_calls",
    format: (v) => v.toLocaleString(),
    color: "text-accent",
    bgColor: "bg-accent/10",
  },
  {
    label: "Blocked",
    key: "blocked_calls",
    format: (v) => v.toLocaleString(),
    color: "text-status-danger",
    bgColor: "bg-status-danger/10",
  },
  {
    label: "Block Rate",
    key: "block_rate_pct",
    format: (v) => `${v}%`,
    color: "text-status-warning",
    bgColor: "bg-status-warning/10",
  },
  {
    label: "Avg Drift",
    key: "avg_drift_score",
    format: (v) => v.toFixed(4),
    color: "text-status-info",
    bgColor: "bg-status-info/10",
  },
  {
    label: "Active Agents",
    key: "active_agents",
    format: (v) => v.toLocaleString(),
    color: "text-status-success",
    bgColor: "bg-status-success/10",
  },
  {
    label: "Total Traces",
    key: "total_traces",
    format: (v) => v.toLocaleString(),
    color: "text-purple-400",
    bgColor: "bg-purple-400/10",
  },
];

export function StatsCards({ stats, loading }: StatsCardsProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
      {STAT_DEFS.map((def) => (
        <div key={def.key} className="card">
          <div className="card-header">{def.label}</div>
          {loading || !stats ? (
            <div className="h-8 w-20 bg-surface-raised rounded animate-pulse" />
          ) : (
            <div className={clsx("text-2xl font-bold", def.color)}>
              {def.format
                ? def.format(stats[def.key] as number)
                : stats[def.key]}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
