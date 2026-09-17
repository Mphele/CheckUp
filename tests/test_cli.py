from unittest.mock import patch

import pytest

from checkup.cli import APP_IMPORT, DEFAULT_HOST, build_parser, main


def test_cli_starts_local_server_with_selected_port() -> None:
    with patch("checkup.cli.uvicorn.run") as run_server:
        main(["--port", "8123", "--reload"])

    run_server.assert_called_once_with(
        APP_IMPORT,
        host=DEFAULT_HOST,
        port=8123,
        reload=True,
    )


def test_cli_rejects_invalid_port() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--port", "70000"])
