import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchPolicies,
  fetchPolicy,
  fetchPolicyVersions,
  createPolicy,
  updatePolicy,
  activatePolicy,
  type PolicyCreatePayload,
} from "@/api/policies";

export function usePolicies(params: { active_only?: boolean } = {}) {
  return useQuery({
    queryKey: ["policies", params],
    queryFn: () => fetchPolicies(params),
  });
}

export function usePolicy(id: string) {
  return useQuery({
    queryKey: ["policy", id],
    queryFn: () => fetchPolicy(id),
    enabled: !!id,
  });
}

export function usePolicyVersions(name: string) {
  return useQuery({
    queryKey: ["policy-versions", name],
    queryFn: () => fetchPolicyVersions(name),
    enabled: !!name,
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: PolicyCreatePayload) => createPolicy(payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string;
      payload: Parameters<typeof updatePolicy>[1];
    }) => updatePolicy(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}

export function useActivatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => activatePolicy(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  });
}
