import { useState } from "react";
import {
  useAlerts,
  useAcknowledgeAlert,
  useResolveAlert,
} from "@/hooks/useAlerts";
import { AlertFeed } from "@/components/alerts/AlertFeed";
import { AlertDetail } from "@/components/alerts/AlertDetail";
import type { Alert } from "@/api/alerts";

export default function AlertsPage() {
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  const { data, isLoading } = useAlerts({
    status: statusFilter || undefined,
    severity: severityFilter || undefined,
  });

  const ackMut = useAcknowledgeAlert();
  const resolveMut = useResolveAlert();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">Alert Center</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            {data ? `${data.total} total alerts` : "Loading..."}
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <select
          className="input w-40"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          className="input w-40"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Split view */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <AlertFeed
          alerts={data?.items ?? []}
          loading={isLoading}
          onSelect={setSelectedAlert}
          selectedId={selectedAlert?.id}
        />

        {selectedAlert ? (
          <AlertDetail
            alert={selectedAlert}
            onAcknowledge={() =>
              ackMut.mutate(selectedAlert.id, {
                onSuccess: (updated) => setSelectedAlert(updated),
              })
            }
            onResolve={() =>
              resolveMut.mutate(selectedAlert.id, {
                onSuccess: (updated) => setSelectedAlert(updated),
              })
            }
            acknowledging={ackMut.isPending}
            resolving={resolveMut.isPending}
          />
        ) : (
          <div className="card py-16 text-center text-sm text-gray-500">
            Select an alert to view details
          </div>
        )}
      </div>
    </div>
  );
}
