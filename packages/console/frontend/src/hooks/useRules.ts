import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  fetchRules,
  createRule,
  deleteRule,
  toggleRule,
  validateRule,
  type RuleDefinition,
} from "@/api/rules";

export function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: fetchRules,
  });
}

export function useCreateRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
}

export function useDeleteRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
}

export function useToggleRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      toggleRule(name, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });
}

export function useValidateRule() {
  return useMutation({
    mutationFn: (rule: RuleDefinition) => validateRule(rule),
  });
}
