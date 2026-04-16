import { useNavigate } from "react-router-dom";
import type { TraceListItem } from "@/api/traces";
import { DataTable, type Column } from "@/components/common/DataTable";
import { IntentDriftBadge } from "./IntentDriftBadge";

interface TraceListProps {
  traces: TraceListItem[];
  loading?: boolean;
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function DecisionBadges({ decisions }: { decisions: string[] }) {
  return (
    <div className="flex gap-1 flex-wrap">
      {decisions.map((d) => {
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
  );
}

const columns: Column<TraceListItem>[] = [
  {
    key: "trace_id",
    header: "Trace ID",
    render: (row) => (
      <span className="font-mono text-xs text-accent">
        {row.trace_id.slice(0, 12)}...
      </span>
    ),
  },
  {
    key: "root_intent",
    header: "Intent",
    render: (row) => (
      <span className="text-gray-200 truncate block max-w-[200px]">
        {row.root_intent || "-"}
      </span>
    ),
  },
  {
    key: "agents",
    header: "Agents",
    render: (row) => (
      <span className="text-xs text-gray-400">
        {(row.agents as string[]).join(", ")}
      </span>
    ),
  },
  {
    key: "span_count",
    header: "Spans",
    render: (row) => <span className="text-gray-300">{row.span_count}</span>,
  },
  {
    key: "max_drift",
    header: "Max Drift",
    render: (row) => <IntentDriftBadge score={row.max_drift} />,
  },
  {
    key: "decisions",
    header: "Decisions",
    render: (row) => <DecisionBadges decisions={row.decisions as string[]} />,
  },
  {
    key: "trace_start",
    header: "Time",
    render: (row) => (
      <span className="text-xs text-gray-400 whitespace-nowrap">
        {formatDate(row.trace_start)}
      </span>
    ),
  },
];

export function TraceList({ traces, loading }: TraceListProps) {
  const navigate = useNavigate();

  return (
    <DataTable
      columns={columns}
      data={traces as any[]}
      loading={loading}
      emptyMessage="No traces found"
      onRowClick={(row) =>
        navigate(`/traces/${(row as unknown as TraceListItem).trace_id}`)
      }
    />
  );
}
