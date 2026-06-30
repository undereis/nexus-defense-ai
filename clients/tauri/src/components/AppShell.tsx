import { useState } from "react";
import { useNexus } from "../lib/useNexus";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { VIEWS } from "../views/registry";
import { ConnectScreen } from "../views/ConnectScreen";

export function AppShell() {
  const { configured } = useNexus();
  const [active, setActive] = useState("dashboard");

  if (!configured) return <ConnectScreen />;

  const entry = VIEWS[active] ?? VIEWS.dashboard;
  const View = entry.Component;

  return (
    <div className="shell">
      <Sidebar active={active} onSelect={setActive} />
      <div className="content">
        <Topbar title={entry.title} />
        <div className="view">
          <View />
        </div>
      </div>
    </div>
  );
}
