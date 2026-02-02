from argparse import ArgumentParser
from pathlib import Path
from typing import List, Set, Any, Dict, ClassVar

from scan2hive.hive.result import HiveResult
from scan2hive.log import LoggerManager
from scan2hive.parsers.base import ScannerParserFactory
from scan2hive.parsers.enums import ToolType, WorkMode
from scan2hive.parsers.helper import register_sub_commands
from scan2hive.uploaders.base import UploaderFactory

logger = LoggerManager.get_logger()


class Utility:
    _parser_keys: ClassVar[Set[str]] = {"input_file", "tag"}
    _hive_uploader_keys: ClassVar[Set[str]] = {"project", "chunk_size", "server"}
    _pipeline_keys: ClassVar[Set[str]] = {"func", "tool", "dry_run", "upload"}

    _phantom_tool: ClassVar[str] = "phantom_tool"

    @classmethod
    def _get_parser_args(cls, raw_args: Dict[str, Any]):
        parser_kwargs = raw_args.copy()
        for it in cls._pipeline_keys | cls._hive_uploader_keys:
            if it in parser_kwargs:
                parser_kwargs.pop(it)

        return parser_kwargs

    @classmethod
    def _get_hive_uploader_args(cls, raw_args: Dict[str, Any]):
        return {it: raw_args[it] for it in cls._hive_uploader_keys}

    @classmethod
    def _dry_run(cls, res: HiveResult, json_output: bool, *args, **kwargs):
        logger.info("Data will not be sent to Hive")
        if json_output:
            print(res.to_json())
        else:
            print(res.to_str())

    @classmethod
    def _upload(cls, res: HiveResult, tool: ToolType, *args, **kwargs):
        uploader_class = UploaderFactory.get(tool)
        uploader = uploader_class(output=res, tool=tool, *args, **kwargs)
        uploader.upload()

    @classmethod
    def handle(cls, args):
        mode = WorkMode.DryRun if args.dry_run else WorkMode.Upload if args.upload else WorkMode.Unknown
        tool = ToolType.from_name(args.tool)

        kwargs = dict(vars(args))

        parser_kwargs = cls._get_parser_args(kwargs)
        parser_klass = ScannerParserFactory.get(tool)
        parser = parser_klass(**parser_kwargs)
        res = parser.handle_source()

        match mode:
            case WorkMode.DryRun:
                cls._dry_run(res, args.json_output)
            case WorkMode.Upload:
                uploader_kwargs = cls._get_hive_uploader_args(kwargs)
                cls._upload(res, tool=tool, **uploader_kwargs)
            case _:
                logger.error(f"Unknown or invalid mode type: '{mode.name}'")
                exit(1)

        pass

    @classmethod
    def _get_args(cls) -> List[str]:
        import sys
        return sys.argv[1:]

    @classmethod
    def setup_args(cls, parser: ArgumentParser):
        parser.set_defaults(func=cls.handle)

        # Modes are mutual exclusive
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--dry-run",
                           help="Do nothing, just show what would be done",
                           action="store_true")
        group.add_argument("--upload",
                           help="Upload results to Hive",
                           action="store_true")

        def add_common_args_stage_1(subparser):
            # Common args for both modes
            subparser.add_argument("-i", "--input",
                                   required=True,
                                   type=Path,
                                   help="Input file",
                                   dest="input_file")
            subparser.add_argument("-t", "--tag",
                                   required=True,
                                   type=str,
                                   help="Tag, e.g. 'egress_<IP>'")

        def add_common_args_stage_2(subparser):
            # Black magic:
            # Remove help args to force skip help default action
            # as we want to add custom args depending on the selected mode

            # Some helpers
            def remove_arg(args: List[str], arg: str):
                args.remove(arg) if arg in args else None

            def add_phantom_arg(args: List[str], phantom: Set[str], phantom_value=None):
                if any([it in args for it in phantom]):
                    return

                args.append(next(iter(phantom)))
                args.append(phantom_value)

            # Get args as is
            args = cls._get_args()

            # Force to remove help, otherwise it will be called inside `parser.parse_known_args(args)`
            remove_arg(args, "-h")
            remove_arg(args, "--help")

            # Add required phantom args as user could skip them in help mode
            add_phantom_arg(args, {cls._phantom_tool})
            add_phantom_arg(args, {"-i", "--input"}, "<phantom-i>")
            add_phantom_arg(args, {"-t", "--tag"}, "<phantom-t>")
            group.required = False

            # Get mode args
            mode_args, _ = parser.parse_known_args(args)

            group.required = True

            # Add specific args for some modes
            if mode_args.dry_run:
                subparser.add_argument("-j", "--json-output",
                                       help="print dry-run output as json, not lines of hosts",
                                       default=False,
                                       action='store_true',
                                       required=False)
            elif mode_args.upload:
                subparser.add_argument("-s", "--server",
                                       required=True,
                                       type=str,
                                       help="Hive server. Example: http://10.10.10.10")
                subparser.add_argument("-p", "--project",
                                       required=True,
                                       type=str,
                                       help="Project UUID. Example: 8f96ef17-f2f1-4056-b401-6c44f7f9156")
                subparser.add_argument("-n", "--chunk-size",
                                       required=False,
                                       type=int,
                                       default=300,
                                       help="Max hosts list length to send in one request (default: 300)")

        # Register sub-commands for different scanner types
        subparsers = parser.add_subparsers(required=True, dest="tool")

        # Add phantom subparser for further BLACK MAGIC (stage 2)
        subparsers.add_parser(cls._phantom_tool)
        register_sub_commands(subparsers, add_common_args_stage_1, add_common_args_stage_2)

        # Remove phantom after everything is done
        del subparsers.choices[cls._phantom_tool]
        tmp = next(
            filter(
                lambda it: it[1].dest == cls._phantom_tool,
                enumerate(subparsers._choices_actions)
            ),
            None
        )
        if tmp:
            idx, item = tmp
            subparsers._choices_actions.pop(idx)
            del item
        pass
