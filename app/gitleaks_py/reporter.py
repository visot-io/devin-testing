class Reporter:
    def __init__(self, config_path=None):
        self.config_path = config_path
    
    def generate_report(self, findings, output_path=None):
        """Mock generating a report."""
        return {
            "status": "success",
            "report_path": output_path or "report.json",
            "findings_count": len(findings)
        }
