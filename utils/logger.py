"""Centralized logging with file rotation"""
import logging, os
from logging.handlers import RotatingFileHandler
from config import Config

def setup_logger(name="ghosttrace"):
    logger = logging.getLogger(name)
    if logger.handlers: return logger
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File
    Config.init()
    fh = RotatingFileHandler(os.path.join(Config.LOG_DIR, "ghosttrace.log"),
                             maxBytes=5*1024*1024, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

log = setup_logger()
