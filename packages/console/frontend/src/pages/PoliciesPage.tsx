import { useState } from "react";
import { usePolicies, useCreatePolicy, useActivatePolicy } from "@/hooks/usePolicies";
import { fetchPolicyVersions, type Policy, type PolicyRule } from "@/api/policies";
import { useQuery } from "@tanstack/react-query";
import { PolicyEditor } from "@/components/policies/PolicyEditor";
import { PolicyVersions } from "@/components/policies/PolicyVersions";

export default function PoliciesPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [newName, setNewName] = useState("");
  const [newRules, setNewRules] = useState<PolicyRule[]>([]);

  const { data: policies, isLoading } = usePolicies();
  const createMut = useCreatePolicy();
  const activateMut = useActivatePolicy();

  // Get unique policy names for version viewing
  const policyNames = [...new Set((policies ?? []).map((p) => p.name))];

  const { data: versions } = useQuery({
    queryKey: ["policy-versions", selectedPolicy?.name],
    queryFn: () => fetchPolicyVersions(selectedPolicy!.name),
    enabled: !!selectedPolicy?.name,
  });

  function handleCreate() {
    if (!newName.trim()) return;
    createMut.mutate(
      {
        name: newName,
        content: { description: `Policy: ${newName}` },
        rules: newRules,
      },
      {
        onSuccess: () => {
          setShowCreate(false);
          setNewName("");
          setNewRules([]);
        },
      }
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">
            Policy Management
          </h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Create, version, and activate security policies
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="btn-primary"
        >
          {showCreate ? "Cancel" : "New Policy"}
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card space-y-4">
          <h3 className="text-sm font-semibold text-gray-200">
            Create New Policy
          </h3>
          <input
            className="input"
            placeholder="Policy name"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
          />
          <PolicyEditor rules={newRules} onChange={setNewRules} />
          <div className="flex justify-end">
            <button
              onClick={handleCreate}
              disabled={createMut.isPending || !newName.trim()}
              className="btn-primary"
            >
              {createMut.isPending ? "Creating..." : "Create Policy"}
            </button>
          </div>
        </div>
      )}

      {/* Policy list + detail split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* List */}
        <div className="lg:col-span-1 space-y-2">
          {isLoading ? (
            <div className="space-y-2">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="h-16 rounded-lg bg-surface-raised animate-pulse"
                />
              ))}
            </div>
          ) : policyNames.length === 0 ? (
            <div className="card py-8 text-center text-sm text-gray-500">
              No policies yet
            </div>
          ) : (
            policyNames.map((name) => {
              const latest = (policies ?? [])
                .filter((p) => p.name === name)
                .sort((a, b) => b.version - a.version)[0];
              if (!latest) return null;
              return (
                <button
                  key={name}
                  onClick={() => setSelectedPolicy(latest)}
                  className={`w-full text-left card transition-colors ${
                    selectedPolicy?.name === name
                      ? "ring-1 ring-accent/30"
                      : "hover:bg-surface-raised"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-200">
                      {name}
                    </span>
                    <span className="text-xs text-gray-500">
                      v{latest.version}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    {latest.is_active ? (
                      <span className="badge badge-success">active</span>
                    ) : (
                      <span className="badge badge-neutral">inactive</span>
                    )}
                    <span className="text-xs text-gray-500">
                      {latest.rules.length} rule
                      {latest.rules.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Detail */}
        <div className="lg:col-span-2 space-y-4">
          {selectedPolicy ? (
            <>
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-gray-100">
                      {selectedPolicy.name}
                    </h3>
                    <span className="text-xs text-gray-500">
                      Version {selectedPolicy.version}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    {!selectedPolicy.is_active && (
                      <button
                        onClick={() =>
                          activateMut.mutate(selectedPolicy.id)
                        }
                        disabled={activateMut.isPending}
                        className="btn-primary text-sm"
                      >
                        {activateMut.isPending
                          ? "Activating..."
                          : "Activate"}
                      </button>
                    )}
                  </div>
                </div>
                <PolicyEditor
                  rules={selectedPolicy.rules}
                  onChange={() => {}}
                  readOnly
                />
              </div>

              {/* Version history */}
              <div className="card">
                <div className="card-header">Version History</div>
                <PolicyVersions
                  versions={versions ?? []}
                  selectedId={selectedPolicy.id}
                  onSelect={setSelectedPolicy}
                />
              </div>
            </>
          ) : (
            <div className="card py-16 text-center text-sm text-gray-500">
              Select a policy to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
