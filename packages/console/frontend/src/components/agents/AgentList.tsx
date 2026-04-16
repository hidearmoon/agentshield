import type { Agent } from "@/api/agents";
import { DataTable, type Column } from "@/components/common/DataTable";

interface AgentListProps {
  agents: Agent[];
  loading?: boolean;
  onSelect: (agent: Agent) => void;
}

const columns: Column<Agent>[] = [
  {
    key: "name",
    header: "Name",
    render: (row) => (
      <span className="text-sm font-medium text-gray-200">{row.name}</span>
    ),
  },
  {
    key: "agent_id",
    header: "Agent ID",
    render: (row) => (
      <span className="text-xs font-mono text-accent">{row.agent_id}</span>
    ),
  },
  {
    key: "description",
    header: "Description",
    render: (row) => (
      <span className="text-xs text-gray-400 truncate block max-w-[300px]">
        {row.description || "-"}
      </span>
    ),
  },
  {
    key: "allowed_tools",
    header: "Tools",
    render: (row) => (
      <div className="flex gap-1 flex-wrap">
        {((row.allowed_tools as string[]) || []).slice(0, 3).map((t) => (
          <span key={t} className="badge badge-neutral">
            {t}
          </span>
        ))}
        {(row.allowed_tools as string[])?.length > 3 && (
          <span className="badge badge-neutral">
            +{(row.allowed_tools as string[]).length - 3}
          </span>
        )}
      </div>
    ),
  },
  {
    key: "updated_at",
    header: "Updated",
    render: (row) => (
      <span className="text-xs text-gray-500">
        {row.updated_at
          ? new Date(row.updated_at).toLocaleDateString()
          : "-"}
      </span>
    ),
  },
];

export function AgentList({ agents, loading, onSelect }: AgentListProps) {
  return (
    <DataTable
      columns={columns}
      data={agents as any[]}
      loading={loading}
      emptyMessage="No agents registered"
      onRowClick={(row) => onSelect(row as Agent)}
    />
  );
}
