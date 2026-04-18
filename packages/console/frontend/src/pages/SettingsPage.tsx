import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch, buildQuery } from "@/api/client";

interface AuditEntry {
  event_id: string;
  event_type: string;
  actor_id: string;
  actor_type: string;
  resource_type: string;
  resource_id: string;
  action: string;
  details: string;
  timestamp: string;
}

function fetchAuditLog(params: Record<string, unknown> = {}): Promise<AuditEntry[]> {
  return apiFetch<AuditEntry[]>(`/audit${buildQuery(params)}`);
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"general" | "audit">("general");
  const [eventTypeFilter, setEventTypeFilter] = useState("");

  const { data: auditLog, isLoading: auditLoading } = useQuery({
    queryKey: ["audit", eventTypeFilter],
    queryFn: () =>
      fetchAuditLog({
        event_type: eventTypeFilter || undefined,
        limit: 100,
      }),
    enabled: activeTab === "audit",
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-semibold text-gray-100">Settings</h2>
        <p className="text-sm text-gray-500 mt-0.5">
          System configuration and audit trail
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {(["general", "audit"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? "border-accent text-gray-100"
                : "border-transparent text-gray-500 hover:text-gray-300"
            }`}
          >
            {tab === "audit" ? "Audit Log" : tab}
          </button>
        ))}
      </div>

      {/* General tab */}
      {activeTab === "general" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-gray-200">
              Console API
            </h3>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                API Base URL
              </label>
              <input
                className="input"
                value="/api/console/v1"
                disabled
              />
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                Core Engine URL
              </label>
              <input
                className="input"
                value="http://localhost:8000"
                disabled
              />
            </div>
          </div>

          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-gray-200">
              Security
            </h3>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                JWT Algorithm
              </label>
              <input className="input" value="HS256" disabled />
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                Token Expiry
              </label>
              <input className="input" value="12 hours" disabled />
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                CORS Origins
              </label>
              <input
                className="input"
                value="localhost:5173, localhost:3000"
                disabled
              />
            </div>
          </div>

          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-gray-200">
              Storage
            </h3>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                PostgreSQL
              </label>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-status-success" />
                <span className="text-sm text-gray-300">Connected</span>
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-500 uppercase block mb-1">
                ClickHouse
              </label>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-status-success" />
                <span className="text-sm text-gray-300">Connected</span>
              </div>
            </div>
          </div>

          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-gray-200">
              Version
            </h3>
            <div className="text-sm text-gray-300">
              <div>
                AgentGuard Console <span className="text-accent">v1.0.0</span>
              </div>
              <div className="text-xs text-gray-500 mt-1">
                Runtime security platform for AI agents
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Audit log tab */}
      {activeTab === "audit" && (
        <div className="space-y-4">
          <div className="flex gap-3">
            <select
              className="input w-48"
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
            >
              <option value="">All event types</option>
              <option value="policy.created">Policy Created</option>
              <option value="policy.activated">Policy Activated</option>
              <option value="agent.created">Agent Created</option>
              <option value="agent.deleted">Agent Deleted</option>
              <option value="alert.acknowledged">Alert Acknowledged</option>
              <option value="source.created">Source Created</option>
            </select>
          </div>

          <div className="card p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-800/50">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Timestamp
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Event
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Actor
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Resource
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Action
                    </th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/30">
                  {auditLoading ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-12 text-center">
                        <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin mx-auto" />
                      </td>
                    </tr>
                  ) : (auditLog ?? []).length === 0 ? (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-12 text-center text-gray-500"
                      >
                        No audit entries found
                      </td>
                    </tr>
                  ) : (
                    (auditLog ?? []).map((entry) => (
                      <tr
                        key={entry.event_id}
                        className="hover:bg-surface-raised/50"
                      >
                        <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">
                          {new Date(entry.timestamp).toLocaleString()}
                        </td>
                        <td className="px-4 py-3">
                          <span className="badge badge-info">
                            {entry.event_type}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-300">
                          <span className="text-gray-500">
                            {entry.actor_type}:
                          </span>{" "}
                          {entry.actor_id.slice(0, 8)}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-300">
                          <span className="text-gray-500">
                            {entry.resource_type}:
                          </span>{" "}
                          {entry.resource_id.slice(0, 12)}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-300">
                          {entry.action}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400 max-w-[200px] truncate">
                          {entry.details}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
