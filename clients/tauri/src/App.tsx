import { NexusProvider } from "./lib/useNexus";
import { AppShell } from "./components/AppShell";

export default function App() {
  return (
    <NexusProvider>
      <AppShell />
    </NexusProvider>
  );
}
