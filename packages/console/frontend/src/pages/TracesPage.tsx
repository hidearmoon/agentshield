import { useState } from "react";
import { useTraces } from "@/hooks/useTraces";
import { TraceList } from "@/components/traces/TraceList";

export default function TracesPage() {
  const [search, setSearch] = useState("");
  const [decision, setDecision] = useState("");
  const [agentId, setAgentId] = useState("");
  const [minDrift, setMinDrift] = useState<string>("");

  const { data, isLoading } = useTraces({
    q: search || undefined,
    decision: decision || undefined,
    agent_id: agentId || undefined,
    min_drift: minDrift ? parseFloat(minDrift) : undefined,
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-100">Trace Explorer</h2>
        <p className="text-sm text-gray-500 mt-0.5">
          Search and inspect agent execution traces
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search intents, tools..."
          className="input w-64"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          className="input w-40"
          value={decision}
          onChange={(e) => setDecision(e.target.value)}
        >
          <option value="">All decisions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="BLOCK">BLOCK</option>
          <option value="REQUIRE_CONFIRMATION">REQUIRE CONFIRMATION</option>
        </select>
        <input
          type="text"
          placeholder="Agent ID"
          className="input w-48"
          value={agentId}
          onChange={(e) => setAgentId(e.target.value)}
        />
        <input
          type="number"
          placeholder="Min drift"
          className="input w-32"
          step="0.1"
          min="0"
          max="1"
          value={minDrift}
          onChange={(e) => setMinDrift(e.target.value)}
        />
      </div>

      <TraceList traces={data ?? []} loading={isLoading} />
    </div>
  );
}
