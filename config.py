import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

CREATOR_NAME = os.getenv("CREATOR_NAME", "Criador")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
MODEL_NAME = os.getenv("NEXUS_MODEL", "claude-sonnet-4-6")

DB_PATH = BASE_DIR / "database" / "nexus.db"

CONNECTIONS_PER_IP_THRESHOLD = 80
MONITOR_WINDOW_SECONDS = 10
MONITOR_POLL_INTERVAL = 5
ALERT_COOLDOWN_SECONDS = 300

PF_ANCHOR_NAME = "nexus_defense"
