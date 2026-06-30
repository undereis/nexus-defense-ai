import { AlertTriangle, Inbox, KeyRound, WifiOff, type LucideIcon } from "lucide-react";

export function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="skel skel-line" style={{ width: `${65 + ((i * 17) % 35)}%` }} />
      ))}
    </div>
  );
}

export function SkeletonCards({ count = 7 }: { count?: number }) {
  return (
    <div className="grid metrics">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="skel skel-card" />
      ))}
    </div>
  );
}

export function EmptyState({
  icon: Icon = Inbox, title, hint,
}: { icon?: LucideIcon; title: string; hint?: string }) {
  return (
    <div className="state">
      <Icon className="state-ico" />
      <h3>{title}</h3>
      {hint ? <p>{hint}</p> : null}
    </div>
  );
}

export function ErrorState({
  kind, message, onRetry,
}: {
  kind: "offline" | "unauthorized" | "error";
  message?: string;
  onRetry?: () => void;
}) {
  const map = {
    offline: {
      icon: WifiOff, title: "API inacessível",
      hint: "Não consegui falar com a API do Nexus. Verifique se o servidor está rodando (uvicorn) e a URL configurada.",
    },
    unauthorized: {
      icon: KeyRound, title: "Token inválido",
      hint: "O token foi recusado (HTTP 401). Revise o token em Configurações.",
    },
    error: {
      icon: AlertTriangle, title: "Erro ao consultar a API",
      hint: "Algo deu errado na consulta.",
    },
  } as const;
  const m = map[kind];
  const Icon = m.icon;
  return (
    <div className="state bad">
      <Icon className="state-ico" />
      <h3>{m.title}</h3>
      <p>{message || m.hint}</p>
      {onRetry ? <button onClick={onRetry}>Tentar de novo</button> : null}
    </div>
  );
}
