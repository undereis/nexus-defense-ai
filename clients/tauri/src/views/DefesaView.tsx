import { ServerCrash, ShieldAlert, UserCog, Zap } from "lucide-react";
import { Gate } from "./_gate";
import { DataPanel } from "../components/DataPanel";
import { CommandCenter } from "../components/CommandCenter";
import { QuickActions } from "../components/QuickActions";
import { OutagesTable } from "../components/Tables";
import { SubscriberAction } from "../components/SubscriberAction";

export function DefesaView() {
  return (
    <Gate>
      {(d) => (
        <div className="grid" style={{ gap: 16 }}>
          <div className="grid cols-main">
            <DataPanel title="Centro de Operações" icon={ShieldAlert}><CommandCenter data={d} /></DataPanel>
            <DataPanel title="Ações rápidas" icon={Zap}><QuickActions /></DataPanel>
          </div>
          <div className="grid cols-2">
            <DataPanel title="Quedas de equipamento" icon={ServerCrash} tight><OutagesTable rows={d.open_outages} /></DataPanel>
            <DataPanel title="Ação por assinante" icon={UserCog}><SubscriberAction /></DataPanel>
          </div>
        </div>
      )}
    </Gate>
  );
}
