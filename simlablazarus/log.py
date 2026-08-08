import logging.config, atexit, json, queue
from pathlib import Path

def setup_log(logger_name: str):
    Path("logs").mkdir(parents=True, exist_ok=True)
    
    config_file = Path("log_config/default.json")
    config = json.loads(config_file.read_text(encoding="utf-8"))
    logging.config.dictConfig(config)
    
    queue_handler = logging.getHandlerByName("queue_handler")
    if queue_handler is not None:
        queue_handler.listener.start()
        atexit.register(queue_handler.listener.stop)
    
    return logging.getLogger(logger_name)
