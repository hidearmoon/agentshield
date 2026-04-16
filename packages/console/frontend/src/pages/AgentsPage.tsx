import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchAgents,
  fetchTopology,
  createAgent,
  deleteAgent,
  type Agent,
} from "@/api/agents";
import { AgentList } from "@/components/agents/AgentList";
import { AgentTopology } from "@/components/agents/AgentTopology";
import { ConfirmDialog } from "@/components/common/ConfirmDialog";
import { clsx } from "clsx";

type ViewMode = "list" | "topology";

export default function AgentsPage() {
  const [view, setView] = useState<ViewMode>("list");
  const [showCreate, setShowCreate] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Agent | null>(null);

  const [newAgentId, setNewAgentId] = useState("");
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");

  const qc = useQueryClient();

  const { data: agents, isLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: () => fetchAgents(),
  });

  const { data: topology } = useQuery({
    queryKey: ["topology"],
    queryFn: () => fetchTopology(24),
    enabled: view === "topology",
  });

  const createMut = useMutation({
    mutationFn: createAgent,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents"] });
      setShowCreate(false);
      setNewAgentId("");
      setNewName("");
      setNewDescription("");
    },
  });

  const deleteMut = useMutation({
    mutationFn: deleteAgent,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agents"] });
      setSelectedAgent(null);
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">
            Agent Registry
          </h2>
          <p className="text-sm text-gray-500 mt-0.5">
            {agents?.length ?? 0} registered agents
          </p>
        </div>
        <div className="flex gap-3">
          {/* View toggle */}
          <div className="inline-flex rounded-lg bg-surface-raised p-1">
            {(["list", "topology"] as const).map((m) => (
              <button
                key={m}
                onClick={() => setView(m)}
                className={clsx(
                  "rounded-md px-3 py-1.5 text-xs font-medium transition-colors capitalize",
                  view === m
                    ? "bg-accent text-white"
                    : "text-gray-400 hover:text-gray-200"
                )}
              >
                {m}
              </button>
            ))}
          </div>
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="btn-primary"
          >
            {showCreate ? "Cancel" : "Register Agent"}
          </button>
        </div>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">
            Register New Agent
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <input
              className="input"
              placeholder="Agent ID"
              value={newAgentId}
              onChange={(e) => setNewAgentId(e.target.value)}
            />
            <input
              className="input"
              placeholder="Display name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
          </div>
          <input
            className="input"
            placeholder="Description (optional)"
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
          />
          <div className="flex justify-end">
            <button
              onClick={() =>
                createMut.mutate({
                  agent_id: newAgentId,
                  name: newName,
                  description: newDescription || undefined,
                })
              }
              disabled={createMut.isPending || !newAgentId || !newName}
              className="btn-primary"
            >
              {createMut.isPending ? "Creating..." : "Register"}
            </button>
          </div>
        </div>
      )}

      {/* Content */}
      {view === "list" ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <AgentList
              agents={agents ?? []}
              loading={isLoading}
              onSelect={setSelectedAgent}
            />
          </div>
          <div>
            {selectedAgent ? (
              <div className="card space-y-4">
                <h3 className="text-lg font-semibold text-gray-100">
                  {selectedAgent.name}
                </h3>
                <dl className="space-y-3 text-sm">
                  <div>
                    <dt className="text-xs text-gray-500 uppercase">
                      Agent ID
                    </dt>
                    <dd className="text-gray-200 font-mono text-xs mt-0.5">
                      {selectedAgent.agent_id}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500 uppercase">
                      Description
                    </dt>
                    <dd className="text-gray-300 mt-0.5">
                      {selectedAgent.description || "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500 uppercase">
                      Allowed Tools
                    </dt>
                    <dd className="flex flex-wrap gap-1 mt-1">
                      {selectedAgent.allowed_tools.length > 0
                        ? selectedAgent.allowed_tools.map((t) => (
                            <span key={t} className="badge badge-neutral">
                              {t}
                            </span>
                          ))
                        : "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-gray-500 uppercase">
                      Created
                    </dt>
                    <dd className="text-gray-400 mt-0.5">
                      {selectedAgent.created_at
                        ? new Date(
                            selectedAgent.created_at
                          ).toLocaleString()
                        : "-"}
                    </dd>
                  </div>
                </dl>
                <button
                  onClick={() => setDeleteTarget(selectedAgent)}
                  className="btn-danger w-full mt-4"
                >
                  Delete Agent
                </button>
              </div>
            ) : (
              <div className="card py-16 text-center text-sm text-gray-500">
                Select an agent to view details
              </div>
            )}
          </div>
        </div>
      ) : (
        topology && <AgentTopology topology={topology} />
      )}

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete Agent"
        description={`Are you sure you want to delete agent "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => {
          if (deleteTarget) deleteMut.mutate(deleteTarget.id);
          setDeleteTarget(null);
        }}
      />
    </div>
  );
}
