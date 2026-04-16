import { useQuery } from "@tanstack/react-query";
import {
  searchTraces,
  fetchTrace,
  type TraceSearchParams,
} from "@/api/traces";

export function useTraces(params: TraceSearchParams = {}) {
  return useQuery({
    queryKey: ["traces", params],
    queryFn: () => searchTraces(params),
  });
}

export function useTrace(traceId: string) {
  return useQuery({
    queryKey: ["trace", traceId],
    queryFn: () => fetchTrace(traceId),
    enabled: !!traceId,
  });
}
