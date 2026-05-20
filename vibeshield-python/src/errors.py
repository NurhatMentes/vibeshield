import random
import string
import logging
import traceback

# Setup default logger
logger = logging.getLogger("VibeShield")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.ERROR)

def generate_tracking_id() -> str:
    """
    Generates a 4-character alphanumeric uppercase tracking ID, prefixed with 'VS-'.
    """
    chars = string.ascii_uppercase + string.digits
    return "VS-" + "".join(random.choices(chars, k=4))

def handle_exception(e: Exception) -> tuple[dict, str]:
    """
    Logs the exception stack trace and returns a safe client response payload with a tracking ID.
    """
    tracking_id = generate_tracking_id()
    
    # Extract and format traceback
    tb_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
    logger.error(f"[{tracking_id}] Unhandled Exception Captured:\n{tb_str}")
    
    masked_payload = {
        "success": False,
        "message": "Internal Server Error",
        "tracking_id": tracking_id
    }
    return masked_payload, tracking_id
