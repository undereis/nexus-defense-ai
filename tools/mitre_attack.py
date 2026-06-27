"""Mapeamento para MITRE ATT&CK: traduz o que a Nexus já detecta (tipo
de evento interno, real, gravado em log_event) para uma TTP
(Tactic/Technique/Procedure) do framework — em vez de só "IP X atacou",
dá contexto de QUAL método, QUE objetivo, e como isso se compara a
campanhas conhecidas.

Isto é uma tabela de mapeamento curada manualmente contra a matriz
pública do MITRE ATT&CK (attack.mitre.org), não uma integração com a
API STIX/TAXII deles — é honesto chamar isso de "mapeamento", não
"integração ao vivo com o MITRE". As chaves abaixo são os event_type
reais que o projeto já grava via log_event (confirmado lendo o código,
não inventado) e os serviços de honeypot (ssh/ftp/http)."""

# event_type real (gravado via log_event) -> (tactic, technique_id, technique_name, descrição)
_EVENT_TTP_MAP: dict[str, tuple[str, str, str, str]] = {
    "ddos_severe": ("Impact", "T1498", "Network Denial of Service",
                     "Volume de tráfego usado para esgotar recursos de rede/serviço."),
    "ddos_suspect": ("Impact", "T1498", "Network Denial of Service",
                       "Padrão de conexões consistente com tentativa de DoS volumétrico."),
    "ssh_command_blocked": ("Execution", "T1059", "Command and Scripting Interpreter",
                              "Tentativa de execução de comando bloqueada pela allowlist de SSH."),
    "ssh_command": ("Execution", "T1059", "Command and Scripting Interpreter",
                      "Comando executado remotamente via SSH (em host de teste autorizado)."),
    "firewall_drift": ("Defense Evasion", "T1562.004", "Disable or Modify System Firewall",
                         "Estado real do firewall divergiu do esperado — possível adulteração ou falha."),
    "sqlmap_attempt": ("Initial Access", "T1190", "Exploit Public-Facing Application",
                         "Tentativa de injeção SQL automatizada contra aplicação web exposta."),
    "hydra_attempt": ("Credential Access", "T1110", "Brute Force",
                        "Tentativa automatizada de adivinhar credenciais válidas contra um serviço."),
    "hashcat_attempt": ("Credential Access", "T1110.002", "Password Cracking",
                          "Quebra offline de hash de senha."),
    "john_attempt": ("Credential Access", "T1110.002", "Password Cracking",
                       "Quebra offline de hash de senha."),
    "mikrotik_firewall_add": ("Defense Evasion", "T1562.004", "Disable or Modify System Firewall",
                                "Alteração de regra de firewall em infraestrutura de rede."),
    "mikrotik_generic_command": ("Execution", "T1059", "Command and Scripting Interpreter",
                                   "Comando executado diretamente no RouterOS."),
    "bgp_flowspec_announced": ("Impact", "T1498.001", "Direct Network Flood",
                                 "Contramedida de roteamento (FlowSpec) anunciada contra tráfego de ataque."),
    "honeypot_error": ("Defense Evasion", "T1562", "Impair Defenses",
                         "Falha ao manter um sensor de detecção (honeypot) operacional."),
    "dpi_started": ("Collection", "T1040", "Network Sniffing",
                      "Início de inspeção profunda de pacotes para visibilidade de tráfego."),
}

# service do honeypot (ssh/ftp/http) -> TTP de quem CONECTOU na armadilha
_HONEYPOT_SERVICE_TTP_MAP: dict[str, tuple[str, str, str, str]] = {
    "ssh": ("Reconnaissance", "T1595", "Active Scanning",
            "Conexão a serviço SSH não documentado — sondagem de superfície de ataque."),
    "ftp": ("Credential Access", "T1110", "Brute Force",
            "Tentativa de autenticação em serviço FTP armadilha — captura de credenciais."),
    "http": ("Credential Access", "T1110", "Brute Force",
             "Tentativa de login via formulário HTTP armadilha — captura de credenciais."),
}

_DEFAULT = ("Unknown", "—", "Sem mapeamento", "Este tipo de evento ainda não tem TTP mapeada.")


def map_event_to_ttp(event_type: str) -> dict:
    """Retorna a TTP mapeada para um tipo de evento interno da Nexus, ou
    um mapeamento 'Unknown' honesto se não houver correspondência."""
    tactic, technique_id, technique_name, description = _EVENT_TTP_MAP.get(event_type, _DEFAULT)
    return {
        "event_type": event_type,
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "description": description,
        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id}/" if technique_id != "—" else "",
    }


def map_honeypot_service_to_ttp(service: str) -> dict:
    """Mesma ideia de map_event_to_ttp, mas para o serviço de honeypot
    que foi tocado (ssh/ftp/http) — honeypot_hits não tem event_type
    próprio na trilha de auditoria, é uma tabela dedicada."""
    tactic, technique_id, technique_name, description = _HONEYPOT_SERVICE_TTP_MAP.get(service, _DEFAULT)
    return {
        "event_type": f"honeypot:{service}",
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "description": description,
        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id}/" if technique_id != "—" else "",
    }


def describe_ttp(event_type: str) -> str:
    ttp = map_event_to_ttp(event_type)
    if ttp["technique_id"] == "—":
        return f"'{event_type}' ainda não tem TTP MITRE ATT&CK mapeada nesta versão da Nexus."
    return (
        f"{event_type} -> {ttp['tactic']} / {ttp['technique_id']} ({ttp['technique_name']})\n"
        f"  {ttp['description']}\n"
        f"  {ttp['mitre_url']}"
    )


def summarize_ttps_for_ip(event_types: list[str], honeypot_services: list[str]) -> str:
    """Resume as TTPs de tudo que se sabe sobre um IP — eventos de
    auditoria (event_types) + serviços de honeypot tocados — agrupando
    por técnica. Usado pelo dossiê de atacante para dar contexto ATT&CK
    em vez de só listar eventos crus."""
    seen: dict[str, dict] = {}
    for et in event_types:
        ttp = map_event_to_ttp(et)
        if ttp["technique_id"] != "—":
            seen.setdefault(ttp["technique_id"], ttp)
    for svc in honeypot_services:
        ttp = map_honeypot_service_to_ttp(svc)
        if ttp["technique_id"] != "—":
            seen.setdefault(ttp["technique_id"], ttp)

    if not seen:
        return "Nenhuma TTP MITRE ATT&CK identificada para os eventos deste IP."
    lines = ["TTPs MITRE ATT&CK identificadas:"]
    for ttp in seen.values():
        lines.append(f"  [{ttp['technique_id']}] {ttp['technique_name']} ({ttp['tactic']}) — {ttp['description']}")
    return "\n".join(lines)
