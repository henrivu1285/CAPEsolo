import os
import tempfile
from contextlib import suppress
from pathlib import Path

from CAPEsolo.capelib.path_utils import path_exists, path_glob, path_is_file
from CAPEsolo.capelib.utils import (
    datefmt,
    dict2list,
    get_detection_by_pid,
    getkey,
    malware_config,
    parentfixup,
    proctreetolist,
    str2list,
)

try:
    from jinja2 import TemplateAssertionError, TemplateNotFound, TemplateSyntaxError, UndefinedError
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader

    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False


class ReportHTML:
    """Stores report in HTML format."""

    def run(self, analysisDir, soloRoot, results):
        """Writes report.
        @param results: CAPE results dict.
        """
        if not HAVE_JINJA2:
            return False, "Failed to generate HTML report: Jinja2 Python library is not installed"

        desktop = Path(os.path.expanduser("~/Desktop"))
        rootDir = Path(soloRoot)
        analysis_path = Path(analysisDir).resolve()
        filepath = analysis_path / "report.html"
        debuggerPath = Path(analysisDir) / "debugger"
        htmlPath = rootDir / "capelib/html"
        debugger = {}
        if path_exists(str(debuggerPath)):
            with suppress(FileNotFoundError, OSError, PermissionError):
                for logPath in sorted(path_glob(str(debuggerPath), "*.log")):
                    if not path_is_file(str(logPath)):
                        continue

                    pid = logPath.stem
                    with open(logPath, "r", encoding="utf-8", errors="replace") as f:
                        debugger[pid] = f.read()

        env = Environment(loader=FileSystemLoader(str(htmlPath)), autoescape=True)
        env.globals["get_detection_by_pid"] = get_detection_by_pid
        env.filters.update(
            {
                "getkey": getkey,
                "str2list": str2list,
                "dict2list": dict2list,
                "parentfixup": parentfixup,
                "malware_config": malware_config,
                "datefmt": datefmt,
                "proctreetolist": proctreetolist,
            }
        )
        # Only surface the Network tab when the summary actually has content; results["network"]
        # is always a dict of (possibly empty) lists, so check for real activity.
        network = results.get("network") or {}
        has_network = any(
            network.get(key)
            for key in ("hosts", "domains", "dns", "http", "tcp", "udp", "tls", "smtp", "icmp", "irc")
        )

        try:
            tpl = env.get_template("report.html")
            html = tpl.render(
                results=results, summary_report=False, debugger=debugger, has_network=has_network
            )
        except UndefinedError as e:
            return False, e
        except TemplateNotFound as e:
            return False, e
        except (TemplateSyntaxError, TemplateAssertionError) as e:
            return False, e

        def write_atomic(destination):
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as report:
                    report.write(html)
                    report.flush()
                    os.fsync(report.fileno())
                os.replace(temp_name, destination)
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name)

        try:
            # The analysis directory is the canonical, run-scoped artifact.
            write_atomic(filepath)
        except OSError as e:
            return False, e

        # Preserve the historical Desktop path for the GUI without allowing a
        # Desktop permission/problem to invalidate the canonical report.
        desktop_path = desktop / "report.html"
        if desktop_path.resolve() != filepath:
            with suppress(OSError):
                write_atomic(desktop_path)
        return True, None
