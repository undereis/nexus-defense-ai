import { useState } from "react";
import { Lock, Unlock, AlertTriangle } from "lucide-react";
import { useNexus } from "../lib/useNexus";

type Pending = null | "block" | "unblock";

// Ação EFETIVA (altera estado no backend, auditada). Exige confirmação
// explícita em duas etapas: o clique apenas arma a confirmação; nada é enviado
// à API sem o "Confirmar".
export function SubscriberAction() {
  const { runAction, actionBusy } = useNexus();
  const [id, setId] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [pending, setPending] = useState<Pending>(null);
  const busy = actionBusy !== null;

  async function exec(kind: "block" | "unblock") {
    setPending(null);
    try {
      const r: any = await runAction(kind, (a) =>
        kind === "block"
          ? a.block(id.trim(), "via cliente Tauri")
          : a.unblock(id.trim(), "via cliente Tauri"),
      );
      setMsg(r?.message || "ok");
    } catch (e: any) {
      setMsg("Erro: " + (e?.message || e));
    }
  }

  function arm(kind: "block" | "unblock") {
    setMsg(null);
    setPending(kind);
  }

  return (
    <div>
      <div className="row">
        <input
          placeholder="id do assinante"
          value={id}
          onChange={(e) => { setId(e.target.value); setPending(null); }}
          style={{ width: 170 }}
        />
        <button onClick={() => arm("block")} disabled={busy || !id.trim()}>
          <Lock size={14} /> Bloquear
        </button>
        <button onClick={() => arm("unblock")} disabled={busy || !id.trim()}>
          <Unlock size={14} /> Desbloquear
        </button>
      </div>

      {pending ? (
        <div className="confirm-box" style={{ marginTop: 10 }}>
          <AlertTriangle size={15} className="confirm-ico" />
          <span>
            Confirmar <strong>{pending === "block" ? "BLOQUEIO" : "DESBLOQUEIO"}</strong> do
            assinante <code>{id.trim()}</code>? Ação efetiva e auditada no backend.
          </span>
          <span className="spacer" />
          <button
            className={pending === "block" ? "danger" : "primary"}
            onClick={() => exec(pending)}
            disabled={busy}
          >
            Confirmar
          </button>
          <button className="ghost" onClick={() => setPending(null)} disabled={busy}>
            Cancelar
          </button>
        </div>
      ) : msg ? (
        <div className="mono-box" style={{ marginTop: 10 }}>{msg}</div>
      ) : (
        <div className="muted-note" style={{ marginTop: 8 }}>
          Bloqueia/desbloqueia um assinante via API real (auditado no backend). Ação efetiva —
          exige confirmação explícita.
        </div>
      )}
    </div>
  );
}
