from osint.core.models import ScanReport


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)
