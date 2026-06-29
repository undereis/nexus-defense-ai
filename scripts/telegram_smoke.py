"""CLI de setup/teste do Telegram (Fase 8).

Lê as credenciais do .env (via config) — NUNCA passe o token na linha de comando
ou no chat. Reinicie o shell/processo após editar o .env (config carrega uma vez).

Uso:
    venv/bin/python scripts/telegram_smoke.py                 # diagnóstico + envia teste
    venv/bin/python scripts/telegram_smoke.py --discover-chat-id [--save]
    venv/bin/python scripts/telegram_smoke.py --set-webhook https://SEU-TUNEL/telegram/webhook
    venv/bin/python scripts/telegram_smoke.py --delete-webhook

Fluxo típico do teste:
    1) preencha TELEGRAM_BOT_TOKEN no .env; adicione o bot ao grupo e mande 1 msg lá
    2) --discover-chat-id --save        (grava TELEGRAM_CHAT_ID no .env)
    3) (sem args)                        (envia mensagem de teste -> outbound OK?)
    4) suba a API + um túnel HTTPS, depois --set-webhook <url>  (inbound)
    5) mande /status no grupo            (o bot responde -> bidirecional OK?)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

import config  # noqa: E402
from tools import telegram  # noqa: E402

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
_TIMEOUT = 10


def _api(method: str):
    return f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/{method}"


def _set_env_var(key: str, value: str) -> None:
    """Atualiza (ou acrescenta) uma chave no .env sem tocar nas outras."""
    lines = _ENV_PATH.read_text().splitlines() if _ENV_PATH.exists() else []
    out, found = [], False
    for ln in lines:
        if ln.startswith(key + "="):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(ln)
    if not found:
        out.append(f"{key}={value}")
    _ENV_PATH.write_text("\n".join(out) + "\n")


def discover_chat_id(save: bool) -> int:
    if not config.TELEGRAM_BOT_TOKEN:
        print("✗ TELEGRAM_BOT_TOKEN vazio no .env. Cole o token do @BotFather primeiro.")
        return 1
    try:
        data = requests.get(_api("getUpdates"), timeout=_TIMEOUT).json()
    except (requests.RequestException, ValueError) as exc:
        print(f"✗ Falha ao chamar getUpdates: {exc}")
        return 1
    if not data.get("ok"):
        print(f"✗ getUpdates falhou: {data.get('description', data)}")
        return 1

    seen = {}
    for upd in data.get("result", []):
        msg = (upd.get("message") or upd.get("edited_message")
               or upd.get("channel_post") or {})
        chat = msg.get("chat") or {}
        if chat.get("id") is not None:
            seen[chat["id"]] = chat.get("title") or chat.get("username") or chat.get("type")

    if not seen:
        print("Nenhum chat encontrado em getUpdates.")
        print("  • Mande uma mensagem NO GRUPO (com o bot já adicionado) e tente de novo.")
        print("  • getUpdates fica VAZIO quando há webhook ativo — rode --delete-webhook antes.")
        return 1

    print("Chats encontrados:")
    for cid, name in seen.items():
        print(f"  chat_id={cid}   ({name})")
    if save:
        chosen = next(iter(seen))
        if len(seen) > 1:
            print(f"\n⚠ Mais de um chat; salvando o primeiro ({chosen}). "
                  "Edite o .env à mão se não for esse.")
        _set_env_var("TELEGRAM_CHAT_ID", str(chosen))
        print(f"✓ TELEGRAM_CHAT_ID={chosen} gravado no .env. Reinicie o processo para valer.")
    else:
        print("\n(rode com --save para gravar o primeiro no .env)")
    return 0


def set_webhook(url: str) -> int:
    print(telegram.set_webhook(url))
    return 0


def webhook_from_ngrok() -> int:
    """Lê a URL pública do ngrok (API local em :4040) e registra o webhook nela.
    Requer `ngrok http 8000` já rodando em outro terminal."""
    try:
        data = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=5).json()
    except (requests.RequestException, ValueError) as exc:
        print(f"✗ ngrok não respondeu em http://127.0.0.1:4040 — está rodando "
              f"('ngrok http 8000')? Detalhe: {exc}")
        return 1
    https = [t.get("public_url", "") for t in data.get("tunnels", [])
             if t.get("public_url", "").startswith("https://")]
    if not https:
        print("✗ Nenhum túnel HTTPS ativo no ngrok.")
        return 1
    url = https[0].rstrip("/") + "/telegram/webhook"
    print(f"Túnel ngrok: {https[0]}")
    print(f"Registrando webhook em {url} ...")
    print(telegram.set_webhook(url))
    return 0


def delete_webhook() -> int:
    if not config.TELEGRAM_BOT_TOKEN:
        print("✗ TELEGRAM_BOT_TOKEN vazio.")
        return 1
    try:
        data = requests.post(_api("deleteWebhook"), timeout=_TIMEOUT).json()
    except (requests.RequestException, ValueError) as exc:
        print(f"✗ Falha: {exc}")
        return 1
    print("✓ Webhook removido." if data.get("ok") else f"✗ {data}")
    return 0


def diagnose_and_send() -> int:
    if not telegram.is_configured():
        print("✗ TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID não configurados no .env.")
        print("  Use --discover-chat-id --save após colar o token e mandar 1 msg no grupo.")
        return 1
    print("=== Diagnóstico (getMe + getWebhookInfo) ===")
    print(telegram.get_webhook_info())
    print(f"\n=== Enviando mensagem de teste para {config.TELEGRAM_CHAT_ID} ===")
    ok = telegram.send_telegram(
        "✅ *Smoke test da Nexus* — se você vê isto, o OUTBOUND do Telegram funciona."
    )
    if ok:
        print("✓ Enviada. Confira o grupo/chat.")
    else:
        print("✗ Falha ao enviar. O bot está no grupo? O chat_id está certo?")
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description="Setup/teste do Telegram (Nexus, Fase 8).")
    p.add_argument("--discover-chat-id", action="store_true", help="lê getUpdates e mostra chat ids")
    p.add_argument("--save", action="store_true", help="com --discover-chat-id, grava no .env")
    p.add_argument("--set-webhook", metavar="URL", help="registra o webhook (https .../telegram/webhook)")
    p.add_argument("--webhook-from-ngrok", action="store_true",
                   help="pega a URL do ngrok (:4040) e registra o webhook nela")
    p.add_argument("--delete-webhook", action="store_true", help="remove o webhook")
    args = p.parse_args()

    if args.discover_chat_id:
        return discover_chat_id(args.save)
    if args.set_webhook:
        return set_webhook(args.set_webhook)
    if args.webhook_from_ngrok:
        return webhook_from_ngrok()
    if args.delete_webhook:
        return delete_webhook()
    return diagnose_and_send()


if __name__ == "__main__":
    sys.exit(main())
