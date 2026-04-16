import { AppRoutes } from "./router";
import { AppShell } from "./components/layout/AppShell";

export function App() {
  return (
    <AppShell>
      <AppRoutes />
    </AppShell>
  );
}
