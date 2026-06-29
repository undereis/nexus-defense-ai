"""Smoke test do Telegram (Fase 8).

Valida, de uma vez, se o canal está vivo:
  1. token (getMe),
  2. OUTBOUND — envia uma mensagem de teste ao TELEGRAM_CHAT_ID,
  3. INBOUND — mostra o estado do webhook (registrado? último erro de entrega?).

Lê tudo do .env (via config) — NUNCA passe o token na linha de comando ou no chat.

Uso:
    venv/bin/python scripts/telegram_smoke.py
"""

import sys

from config import TELEGRAM_CHAT_ID
from tools import telegram


def main() -> int:
    if not telegram.is_configured():
        print("✗ TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID não configurados no .env.")
        print("  Configure-os e reinicie. Veja .env.example.")
        return 1

    print("=== Diagnóstico (getMe + getWebhookInfo) ===")
    print(telegram.get_webhook_info())

    print(f"\n=== Enviando mensagem de teste para {TELEGRAM_CHAT_ID} ===")
    ok = telegram.send_telegram(
        "✅ *Smoke test da Nexus* — se você está vendo isto, o OUTBOUND do Telegram funciona."
    )
    if ok:
        print("✓ Enviada. Confira o grupo/chat.")
    else:
        print("✗ Falha ao enviar. Causas comuns: chat_id errado, ou o bot ainda não foi "
              "adicionado ao grupo / não recebeu a 1ª mensagem do grupo.")

    print(
        "\nPara o INBOUND (operar pelo grupo), o webhook precisa estar registrado e SEM erro "
        "de entrega acima. Se estiver 'NÃO registrado', exponha a API por HTTPS e rode "
        "setup_telegram_webhook(url)."
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
