import logging
import sys

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s | %(name)s | %(levelname)s | %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.logger = get_logger(name)

    def analyze(self, data) -> dict:
        raise NotImplementedError
