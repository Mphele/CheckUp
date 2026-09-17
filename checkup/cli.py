import argparse
from collections.abc import Sequence

import uvicorn


APP_IMPORT = "checkup.main:app"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkup",
        description="Run the CheckUp security review dashboard locally.",
    )
    parser.add_argument(
        "--port",
        type=_valid_port,
        default=DEFAULT_PORT,
        help=f"Local port to use (default: {DEFAULT_PORT}).",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Restart the server automatically when CheckUp source files change.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    arguments = build_parser().parse_args(argv)
    uvicorn.run(
        APP_IMPORT,
        host=DEFAULT_HOST,
        port=arguments.port,
        reload=arguments.reload,
    )


def _valid_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port

