import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import type { TrafficPoint } from "@/api/dashboard";

interface TrafficChartProps {
  data: TrafficPoint[];
  loading?: boolean;
}

function formatTime(value: string) {
  const d = new Date(value);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function TrafficChart({ data, loading }: TrafficChartProps) {
  return (
    <div className="card">
      <div className="card-header">Traffic Over Time</div>
      {loading ? (
        <div className="h-64 flex items-center justify-center">
          <div className="w-6 h-6 border-2 border-accent border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <LineChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2235" />
            <XAxis
              dataKey="bucket"
              tickFormatter={formatTime}
              stroke="#4b5563"
              fontSize={11}
              tickLine={false}
            />
            <YAxis stroke="#4b5563" fontSize={11} tickLine={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#1c2030",
                border: "1px solid #2a2f3f",
                borderRadius: "8px",
                fontSize: "12px",
              }}
              labelFormatter={formatTime}
            />
            <Legend
              wrapperStyle={{ fontSize: "12px" }}
              iconType="circle"
              iconSize={8}
            />
            <Line
              type="monotone"
              dataKey="total"
              stroke="#6366f1"
              strokeWidth={2}
              dot={false}
              name="Total"
            />
            <Line
              type="monotone"
              dataKey="allowed"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              name="Allowed"
            />
            <Line
              type="monotone"
              dataKey="blocked"
              stroke="#ef4444"
              strokeWidth={2}
              dot={false}
              name="Blocked"
            />
            <Line
              type="monotone"
              dataKey="confirm"
              stroke="#f59e0b"
              strokeWidth={2}
              dot={false}
              name="Confirm"
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
