import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { DriftPoint } from "@/api/dashboard";

interface IntentDriftChartProps {
  data: DriftPoint[];
  loading?: boolean;
}

function formatTime(value: string) {
  const d = new Date(value);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function IntentDriftChart({ data, loading }: IntentDriftChartProps) {
  return (
    <div className="card">
      <div className="card-header">Intent Drift Score</div>
      {loading ? (
        <div className="h-64 flex items-center justify-center">
          <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <AreaChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
            <defs>
              <linearGradient id="driftGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="maxDriftGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ef4444" stopOpacity={0.2} />
                <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2235" />
            <XAxis
              dataKey="bucket"
              tickFormatter={formatTime}
              stroke="#4b5563"
              fontSize={11}
              tickLine={false}
            />
            <YAxis
              stroke="#4b5563"
              fontSize={11}
              tickLine={false}
              domain={[0, 1]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1c2030",
                border: "1px solid #2a2f3f",
                borderRadius: "8px",
                fontSize: "12px",
              }}
              labelFormatter={formatTime}
            />
            <Area
              type="monotone"
              dataKey="max_drift"
              stroke="#ef4444"
              strokeWidth={1.5}
              fill="url(#maxDriftGrad)"
              name="Max Drift"
            />
            <Area
              type="monotone"
              dataKey="avg_drift"
              stroke="#f59e0b"
              strokeWidth={2}
              fill="url(#driftGrad)"
              name="Avg Drift"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
