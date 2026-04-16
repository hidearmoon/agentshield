import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchDashboard } from "@/api/dashboard";
import { StatsCards } from "@/components/dashboard/StatsCards";
import { TrafficChart } from "@/components/dashboard/TrafficChart";
import { IntentDriftChart } from "@/components/dashboard/IntentDriftChart";
import { RiskRanking } from "@/components/dashboard/RiskRanking";
import { TimeRangePicker } from "@/components/common/TimeRangePicker";

export default function DashboardPage() {
  const [hours, setHours] = useState(24);

  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", hours],
    queryFn: () => fetchDashboard(hours),
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">Overview</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Real-time security metrics across all agents
          </p>
        </div>
        <TimeRangePicker value={hours} onChange={setHours} />
      </div>

      <StatsCards stats={data?.summary} loading={isLoading} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TrafficChart data={data?.traffic ?? []} loading={isLoading} />
        <IntentDriftChart data={data?.intent_drift ?? []} loading={isLoading} />
      </div>

      <RiskRanking data={data?.risk_ranking ?? []} loading={isLoading} />
    </div>
  );
}
