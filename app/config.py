import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Settings:
    bind: str = os.getenv("DASHBOARD_BIND", "127.0.0.1:8787")
    secret_key: str = os.getenv("DASHBOARD_SECRET_KEY", "dev-secret-change-me")
    password_hash: str = os.getenv("DASHBOARD_PASSWORD_HASH", "")

    clash_api_url: str = os.getenv("CLASH_API_URL", "http://127.0.0.1:9090")
    clash_api_secret: str = os.getenv("CLASH_API_SECRET", "")

    singbox_config: str = os.getenv("SINGBOX_CONFIG", "/etc/sing-box/config.json")
    singbox_ruleset: str = os.getenv("SINGBOX_RULESET", "/etc/sing-box/rules/proxied.json")
    singbox_bin: str = os.getenv("SINGBOX_BIN", "/usr/bin/sing-box")

    proxy_port: int = int(os.getenv("PROXY_PORT", "1080"))
    staging_port: int = int(os.getenv("STAGING_PORT", "11080"))
    staging_api_port: int = int(os.getenv("STAGING_API_PORT", "19090"))

    health_targets: list[str] = [
        t.strip()
        for t in os.getenv(
            "HEALTH_TARGETS", "https://api.telegram.org,https://discord.com/api/v10/gateway"
        ).split(",")
        if t.strip()
    ]

    db_path: str = os.getenv("DB_PATH", str(Path(__file__).parent.parent / "data" / "dashboard.db"))
    hermes_config_path: str = os.getenv("HERMES_CONFIG_PATH", "/opt/hermes/config.yaml")

    @property
    def host(self) -> str:
        return self.bind.split(":")[0]

    @property
    def port(self) -> int:
        return int(self.bind.split(":")[1])


settings = Settings()
