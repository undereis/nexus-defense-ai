import { NexusProvider } from "./lib/useNexus";
import { EnvironmentProvider } from "./lib/environment";
import { AppShell } from "./components/AppShell";

export default function App() {
  return (
    <EnvironmentProvider>
      <NexusProvider>
        <AppShell />
      </NexusProvider>
    </EnvironmentProvider>
  );
}
