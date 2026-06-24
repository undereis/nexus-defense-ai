"""Nexus Defense AI — ponto de entrada.

Roda localmente: um chat com o criador em primeiro plano e, em segundo
plano, um monitor de rede que aciona o agente automaticamente quando
detecta possíveis ataques (ex.: DDoS), permitindo que ele decida isolar
a origem do ataque.
"""

import threading
import time

from agents.nexus_agent import build_agent, _detector
from config import ALERT_COOLDOWN_SECONDS, CREATOR_NAME, MONITOR_POLL_INTERVAL
from database.db import init_db, log_event
from memory import memory_store

_agent = None
_lock = threading.Lock()
_last_alerted: dict[str, float] = {}


def get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


def ask_agent(user_text: str) -> str:
    agent = get_agent()
    history = memory_store.load_history(limit=20)
    messages = [(m["role"], m["content"]) for m in history] + [("user", user_text)]
    with _lock:
        result = agent.invoke({"messages": messages})
    reply = result["messages"][-1].content
    memory_store.remember("user", user_text)
    memory_store.remember("assistant", reply)
    return reply


def monitor_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            suspects = _detector.sample()
            now = time.time()
            new_suspects = [
                ip for ip in suspects
                if now - _last_alerted.get(ip, 0) >= ALERT_COOLDOWN_SECONDS
            ]
            if new_suspects:
                for ip in new_suspects:
                    log_event("ddos_suspect", ip, "Limite de conexões excedido na janela de monitoramento")
                    _last_alerted[ip] = now
                alert = (
                    "ALERTA AUTOMÁTICO DO MONITOR DE REDE: os seguintes IPs excederam o "
                    f"limite de conexões na janela de monitoramento e são suspeitos de DDoS: "
                    f"{', '.join(new_suspects)}. Avalie e decida se deve isolá-los, explicando o motivo."
                )
                print(f"\n[Nexus] Anomalia detectada, analisando...")
                reply = ask_agent(alert)
                print(f"\n[Nexus] {reply}\n> ", end="", flush=True)
        except Exception as exc:
            log_event("monitor_error", None, str(exc))
        stop_event.wait(MONITOR_POLL_INTERVAL)


def main():
    init_db()
    print("=== Nexus Defense AI ===")
    print(f"Online. Olá, {CREATOR_NAME}. Estou monitorando a rede em segundo plano.")
    print("Digite 'sair' para encerrar.\n")

    stop_event = threading.Event()
    monitor_thread = threading.Thread(target=monitor_loop, args=(stop_event,), daemon=True)
    monitor_thread.start()

    try:
        while True:
            user_text = input("> ").strip()
            if not user_text:
                continue
            if user_text.lower() in {"sair", "exit", "quit"}:
                break
            try:
                reply = ask_agent(user_text)
                print(f"\n[Nexus] {reply}\n")
            except Exception as exc:
                log_event("chat_error", None, str(exc))
                print(f"\n[Nexus] Tive um erro interno processando isso: {exc}\n")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stop_event.set()
        print("\nNexus Defense AI encerrada.")


if __name__ == "__main__":
    main()
