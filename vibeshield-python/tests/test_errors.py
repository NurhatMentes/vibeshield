import re
from src.errors import handle_exception, generate_tracking_id

def test_generate_tracking_id():
    tid = generate_tracking_id()
    assert re.match(r"^VS-[A-Z0-9]{4}$", tid)

def test_handle_exception():
    try:
        raise ValueError("Sensitive database connection lost!")
    except Exception as e:
        payload, tracking_id = handle_exception(e)
        
        # Verify the tracking ID
        assert re.match(r"^VS-[A-Z0-9]{4}$", tracking_id)
        assert payload["tracking_id"] == tracking_id
        
        # Verify safety boundaries
        assert payload["success"] is False
        assert "Sensitive database connection" not in payload["message"]
        assert payload["message"] == "Internal Server Error"
