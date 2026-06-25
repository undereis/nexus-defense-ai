"""Verificação de assinatura de requisições do Slack.

Sem isso, o endpoint /slack/command seria um jeito de qualquer pessoa
na internet mandar comandos para um agente que pode isolar IPs e
executar SSH em hosts — verificação de assinatura não é opcional aqui,
é o que garante que só o Slack do criador pode falar com a Nexus por
esse canal.

Algoritmo oficial do Slack: https://api.slack.com/authentication/verifying-requests-from-slack
"""

import hashlib
import hmac
import time


def verify_signature(
    signing_secret: str, timestamp: str, body: str, signature: str, max_age_seconds: int = 300
) -> bool:
    """True se a assinatura é válida E a requisição é recente (evita replay)."""
    if not signing_secret or not timestamp or not signature:
        return False

    try:
        ts = int(timestamp)
    except ValueError:
        return False

    if abs(time.time() - ts) > max_age_seconds:
        return False

    basestring = f"v0:{timestamp}:{body}".encode("utf-8")
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), basestring, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)
