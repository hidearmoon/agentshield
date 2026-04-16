import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch, buildQuery } from "@/api/client";
import { DataTable, type Column } from "@/components/common/DataTable";
import { clsx } from "clsx";

interface Source {
  id: string;
  source_id: string;
  trust_level: string;
  reputation_score: number;
  description: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

function fetchSources(params: { trust_level?: string } = {}): Promise<Source[]> {
  return apiFetch<Source[]>(`/sources${buildQuery(params)}`);
}

export default function SourcesPage() {
  const [trustFilter, setTrustFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [newSourceId, setNewSourceId] = useState("");
  const [newTrust, setNewTrust] = useState("semi_trusted");
  const [newDesc, setNewDesc] = useState("");

  const qc = useQueryClient();

  const { data: sources, isLoading } = useQuery({
    queryKey: ["sources", trustFilter],
    queryFn: () => fetchSources({ trust_level: trustFilter || undefined }),
  });

  const createMut = useMutation({
    mutationFn: (payload: { source_id: string; trust_level: string; description?: string }) =>
      apiFetch<Source>("/sources", { method: "POST", body: JSON.stringify(payload) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sources"] });
      setShowCreate(false);
      setNewSourceId("");
      setNewDesc("");
    },
  });

  const recalcMut = useMutation({
    mutationFn: (id: string) =>
      apiFetch<Source>(`/sources/${id}/recalculate`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sources"] }),
  });

  function ReputationBar({ score }: { score: number }) {
    const pct = Math.round(score * 100);
    return (
      <div className="flex items-center gap-2">
        <div className="w-24 h-2 rounded-full bg-surface-overlay overflow-hidden">
          <div
            className={clsx(
              "h-full rounded-full",
              score >= 0.7
                ? "bg-status-success"
                : score >= 0.4
                  ? "bg-status-warning"
                  : "bg-status-danger"
            )}
            style={{ width: `${pct}%` }}
          />
        </div>
        <span className="text-xs font-mono text-gray-400">{pct}%</span>
      </div>
    );
  }

  const columns: Column<Source>[] = [
    {
      key: "source_id",
      header: "Source ID",
      render: (row) => (
        <span className="font-mono text-xs text-accent">{row.source_id}</span>
      ),
    },
    {
      key: "trust_level",
      header: "Trust Level",
      render: (row) => {
        const cls =
          row.trust_level === "trusted"
            ? "badge-success"
            : row.trust_level === "semi_trusted"
              ? "badge-warning"
              : "badge-danger";
        return <span className={`badge ${cls}`}>{row.trust_level}</span>;
      },
    },
    {
      key: "reputation_score",
      header: "Reputation",
      render: (row) => <ReputationBar score={row.reputation_score} />,
    },
    {
      key: "description",
      header: "Description",
      render: (row) => (
        <span className="text-xs text-gray-400 truncate block max-w-[200px]">
          {row.description || "-"}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (row) => (
        <button
          onClick={(e) => {
            e.stopPropagation();
            recalcMut.mutate(row.id);
          }}
          disabled={recalcMut.isPending}
          className="btn-ghost text-xs"
        >
          Recalculate
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">Data Sources</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Manage data sources and reputation scores
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="btn-primary"
        >
          {showCreate ? "Cancel" : "Add Source"}
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">
            Add Data Source
          </h3>
          <div className="grid grid-cols-3 gap-4">
            <input
              className="input"
              placeholder="Source ID"
              value={newSourceId}
              onChange={(e) => setNewSourceId(e.target.value)}
            />
            <select
              className="input"
              value={newTrust}
              onChange={(e) => setNewTrust(e.target.value)}
            >
              <option value="trusted">Trusted</option>
              <option value="semi_trusted">Semi-trusted</option>
              <option value="untrusted">Untrusted</option>
            </select>
            <input
              className="input"
              placeholder="Description"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
            />
          </div>
          <div className="flex justify-end">
            <button
              onClick={() =>
                createMut.mutate({
                  source_id: newSourceId,
                  trust_level: newTrust,
                  description: newDesc || undefined,
                })
              }
              disabled={createMut.isPending || !newSourceId}
              className="btn-primary"
            >
              {createMut.isPending ? "Adding..." : "Add Source"}
            </button>
          </div>
        </div>
      )}

      {/* Filter */}
      <div className="flex gap-3">
        <select
          className="input w-48"
          value={trustFilter}
          onChange={(e) => setTrustFilter(e.target.value)}
        >
          <option value="">All trust levels</option>
          <option value="trusted">Trusted</option>
          <option value="semi_trusted">Semi-trusted</option>
          <option value="untrusted">Untrusted</option>
        </select>
      </div>

      <DataTable
        columns={columns}
        data={(sources ?? []) as any[]}
        loading={isLoading}
        emptyMessage="No data sources registered"
      />
    </div>
  );
}
