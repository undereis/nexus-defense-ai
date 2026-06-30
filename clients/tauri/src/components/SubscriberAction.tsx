import { useState } from "react";
import { Lock, Unlock } from "lucide-react";
import { useNexus } from "../lib/useNexus";

export function SubscriberAction() {
  const { runAction, actionBusy } = useNexus();
  const [id, setId] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const busy = actionBusy !== null;

  async function block() {
    try {
      const r: any = await runAction("block", (a) => a.block(id.trim(), "via cliente Tauri"));
      setMsg(r?.message || "ok");
    } catch (e: any) {
      setMsg("Erro: " + (e?.message || e));
    }
  }
  async function unblock() {
    try {
      const r: any = await runAction("unblock", (a) => a.unblock(id.trim(), "via cliente Tauri"));
      setMsg(r?.message || "ok");
    } catch (e: any) {
      setMsg("Erro: " + (e?.message || e));
    }
  }

  return (
    <div>
      <div className="row">
        <input placeholder="id do assinante" value={id} onChange={(e) => setId(e.target.value)} style={{ width: 170 }} />
        <button onClick={block} disabled={busy || !id.trim()}><Lock size={14} /> Bloquear</button>
        <button onClick={unblock} disabled={busy || !id.trim()}><Unlock size={14} /> Desbloquear</button>
      </div>
      {msg ? (
        <div className="mono-box" style={{ marginTop: 10 }}>{msg}</div>
      ) : (
        <div className="muted-note" style={{ marginTop: 8 }}>
          Bloqueia/desbloqueia um assinante via API real (auditado no backend). Ação efetiva — use com cuidado.
        </div>
      )}
    </div>
  );
}
