from argparse import ArgumentParser

from scan2hive.log import LogLevel, LoggerManager
from scan2hive.utils.utility import Utility


def setup_args() -> ArgumentParser:
    parser = ArgumentParser("scan2hive",
                            description="Tool for importing scan results to Hive",
                            )

    Utility.setup_args(parser)

    return parser


def entry():
    LoggerManager.set_root_log_level(LogLevel.Debug)
    LoggerManager.set_stream_log_level(LogLevel.Info)

    parser = setup_args()
    args = parser.parse_args()
    args.func(args)
