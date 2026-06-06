from __future__ import annotations

import json
import csv
import os
import logging
import pandas as pd # Assuming pandas is installed for CSV export

logger = logging.getLogger(__name__)

def export_logs(events: list[dict], format_type: str, filename_prefix: str = "events", directory: str = ".") -> str | None:
    """
    Exports a list of security events to a specified file format (JSON or CSV).

    Args:
        events (list[dict]): A list of event dictionaries to export.
        format_type (str): The desired export format ('json' or 'csv').
        filename_prefix (str): The prefix for the output filename.
        directory (str): The directory where the file should be saved. Defaults to current directory.

    Returns:
        str | None: The absolute path to the exported file if successful, None otherwise.
    """
    if not events:
        logger.warning("Δεν υπάρχουν συμβάντα για εξαγωγή")
        return None

    # Ensure the directory exists
    os.makedirs(directory, exist_ok=True)

    if format_type == "json":
        file_path = os.path.join(directory, f"{filename_prefix}.json")
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(events, f, indent=2, default=str)
            logger.info(f"Events exported successfully to {file_path}")
            return os.path.abspath(file_path) # Return absolute path
        except IOError as e:
            logger.error(f"Σφάλμα κατά την εξαγωγή σε JSON: {e}")
            return None
    elif format_type == "csv":
        file_path = os.path.join(directory, f"{filename_prefix}.csv")
        try:
            df = pd.DataFrame(events)
            df.to_csv(file_path, index=False, encoding="utf-8")
            logger.info(f"Events exported successfully to {file_path}")
            return os.path.abspath(file_path) # Return absolute path
        except Exception as e:
            logger.error(f"Σφάλμα κατά την εξαγωγή σε CSV: {e}")
            return None
    else:
        logger.error(f"Unsupported format: {format_type}")
        return None

