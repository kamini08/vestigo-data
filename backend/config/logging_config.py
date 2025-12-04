"""
Logging configuration for Vestigo backend
Provides structured logging for the entire analysis pipeline
"""

import logging
import logging.config
import os
from datetime import datetime

def setup_logging():
    """Configure logging for the application"""
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    # Generate timestamped log file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(logs_dir, f"vestigo_{timestamp}.log")
    
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "detailed": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
            },
            "simple": {
                "format": "%(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "INFO",
                "formatter": "simple",
                "stream": "ext://sys.stdout"
            },
            "file": {
                "class": "logging.FileHandler",
                "level": "DEBUG",
                "formatter": "detailed",
                "filename": log_file,
                "mode": "a"
            }
        },
        "loggers": {
            "vestigo": {
                "level": "DEBUG",
                "handlers": ["console", "file"],
                "propagate": False
            }
        },
        "root": {
            "level": "INFO",
            "handlers": ["console"]
        }
    }
    
    logging.config.dictConfig(logging_config)
    
    # Return the main application logger
    logger = logging.getLogger("vestigo")
    logger.info(f"Logging initialized - Log file: {log_file}")
    
    return logger

# Global logger instance
logger = setup_logging()