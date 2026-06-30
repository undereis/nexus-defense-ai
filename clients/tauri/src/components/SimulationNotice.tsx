import { FlaskConical } from "lucide-react";

// Rótulo reutilizável para conteúdo de demonstração (modo Laboratório). Deixa
// explícito que aquilo NÃO é telemetria real. Evita a palavra "mock" na UI.
export function SimulationNotice({
  text = "Simulação visual — demo local",
  inline = false,
}: { text?: string; inline?: boolean }) {
  if (inline) {
    return (
      <span className="sim-tag">
        <FlaskConical size={10} /> {text}
      </span>
    );
  }
  return (
    <div className="sim-notice">
      <FlaskConical size={13} />
      <span>{text}</span>
    </div>
  );
}
