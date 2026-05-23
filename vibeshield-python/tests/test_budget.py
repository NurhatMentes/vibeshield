import pytest
from unittest.mock import patch, MagicMock
from src.budget import global_budget_tracker
from src.fetch import vibe_fetch

@pytest.fixture(autouse=True)
def reset_budget_state():
    global_budget_tracker.reset_for_test()
    yield
    global_budget_tracker.reset_for_test()

def test_budget_tracker_max_daily_requests():
    options = {"enabled": True, "maxDailyRequests": 2}
    
    global_budget_tracker.track_request(options) # Req 1
    global_budget_tracker.track_request(options) # Req 2
    
    assert global_budget_tracker.get_requests() == 2
    
    with pytest.raises(Exception, match="VIBESHIELD BUDGET EXCEEDED"):
        global_budget_tracker.track_request(options)

def test_budget_tracker_daily_dollar_limit():
    options = {"enabled": True, "dailyDollarLimit": 1.00, "estimatedCostPerToken": 0.01}
    
    global_budget_tracker.track_cost(options, 50)
    assert global_budget_tracker.get_cost() == 0.50
    
    global_budget_tracker.track_cost(options, 60)
    assert global_budget_tracker.get_cost() == 1.10
    
    with pytest.raises(Exception, match="VIBESHIELD BUDGET EXCEEDED"):
        global_budget_tracker.track_request(options)

def test_budget_tracker_disabled():
    options = {"enabled": False, "maxDailyRequests": 1}
    global_budget_tracker.track_request(options)
    global_budget_tracker.track_request(options) # Should not throw
    assert global_budget_tracker.get_requests() == 0

@pytest.mark.asyncio
@patch('urllib.request.urlopen')
async def test_vibe_fetch_pass_through(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.getheaders.return_value = [("Content-Type", "application/json")]
    mock_response.read.return_value = b'{"ok": true}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    options = {"budget": {"enabled": True, "maxDailyRequests": 5}}
    
    status, headers, body = await vibe_fetch("https://api.openai.com/v1/chat", options=options)
    
    assert status == 200
    assert global_budget_tracker.get_requests() == 1
    mock_urlopen.assert_called_once()

@pytest.mark.asyncio
@patch('urllib.request.urlopen')
async def test_vibe_fetch_short_circuit_exceeded(mock_urlopen):
    options = {"budget": {"enabled": True, "maxDailyRequests": 1}}
    
    mock_response = MagicMock()
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    await vibe_fetch("https://api.test/1", options=options)
    
    with pytest.raises(Exception, match="VIBESHIELD BUDGET EXCEEDED"):
        await vibe_fetch("https://api.test/2", options=options)
        
    assert mock_urlopen.call_count == 1

@pytest.mark.asyncio
@patch('urllib.request.urlopen')
async def test_vibe_fetch_dynamic_token_parsing(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.getheaders.return_value = [("Content-Type", "application/json")]
    mock_response.read.return_value = b'{"usage": {"total_tokens": 100}}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    options = {"budget": {"enabled": True, "estimatedCostPerToken": 0.01, "dailyDollarLimit": 5.00}}
    
    await vibe_fetch("https://api.openai.com", options=options)
    
    assert global_budget_tracker.get_cost() == 1.00 # 100 * 0.01
