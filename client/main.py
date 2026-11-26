"""Entry point for the visible client agent."""

from __future__ import annotations

import argparse

from client.authentication import load_or_create_identity
from client.config import load_settings
from client.gui.app import ClientApp


def main() -> None:
    parser = argparse.ArgumentParser(description="Remote Administration Lab — Client")
    parser.add_argument("--settings", default=None, help="path ke settings.json")
    parser.add_argument("--identity", default=None, help="path ke identity.blob")
    args = parser.parse_args()

    settings = load_settings(args.settings)
    identity = load_or_create_identity(args.identity)
    app = ClientApp(settings, identity, args.settings, args.identity)
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()


if __name__ == "__main__":
    main()
