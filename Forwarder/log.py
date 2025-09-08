import logging
import sys


def setup_logging(log_file='forwarder.log'):
    """
    Configures the root logger for the entire application.
    - Logs to both a file and the console.
    - Sets a standardized format for log messages.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s - %(asctime)s - [%(name)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )


setup_logging()
logger = logging.getLogger("forwarder")
