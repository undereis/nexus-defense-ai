import {
  Database, FlaskConical, History, WifiOff, KeyRound, CircleDot, type LucideIcon,
} from "lucide-react";
import { useNexus } from "../lib/useNexus";
import { useEnvironment } from "../lib/environment";

type Tone = "ok" | "warn" | "bad" | "info" | "neutral";

// Indicador GLOBAL de fonte dos dados — faixa fina sob a Topbar, presente em
// toda tela. Combina o modo de ambiente com o estado da conexão para que o
// operador saiba em segundos se vê telemetria real, parcial, ilustrativa ou
// indisponível. Nunca apresenta dado simulado como real.
export function DataSourceBanner() {
  const { status, data } = useNexus();
  const { mode } = useEnvironment();

  let tone: Tone = "info";
  let Icon: LucideIcon = Database;
  let title = "";
  let detail = "";

  if (mode === "replay") {
    tone = "neutral"; Icon = History;
    title = "Modo Replay";
    detail = "Reprodução de eventos — indisponível na API atual. Nenhum dado é simulado como real.";
  } else if (mode === "lab") {
    tone = "warn"; Icon = FlaskConical;
    title = "Modo Laboratório / Simulado";
    detail = "Visualizações ilustrativas marcadas como “Simulação visual”. As métricas continuam reais quando vindas da API.";
  } else if (status === "ok") {
    tone = "ok"; Icon = Database;
    title = "Modo Real · Dados reais da API";
    detail = data && data.devices.total === 0
      ? "Sem laboratório/hardware conectado ainda — telemetria física aguardando equipamentos."
      : "Telemetria proveniente do motor Python via API REST.";
  } else if (status === "unauthorized") {
    tone = "bad"; Icon = KeyRound;
    title = "Token inválido";
    detail = "A API recusou o token (HTTP 401). Ajuste em Configurações.";
  } else if (status === "offline") {
    tone = "bad"; Icon = WifiOff;
    title = "API offline";
    detail = data
      ? "Exibindo o último estado conhecido — pode estar vencido."
      : "Sem conexão com o motor Python.";
  } else {
    tone = "neutral"; Icon = CircleDot;
    title = "Aguardando conexão";
    detail = "Configure URL e token para receber telemetria real.";
  }

  return (
    <div className={`ds-banner ${tone}`}>
      <Icon size={15} className="ds-ico" />
      <strong>{title}</strong>
      <span className="ds-detail">{detail}</span>
    </div>
  );
}
