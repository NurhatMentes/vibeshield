from src.sanitizer import sanitize

def test_sanitize_strings_basic():
    assert sanitize("hello") == "hello"
    assert sanitize(123) == 123
    assert sanitize(None) is None

def test_sanitize_xss_attacks():
    # Strip script tags
    assert sanitize("<script>alert(1)</script>") == ""
    # Strip nested script tags
    assert sanitize("<script>malicious</script>Clean Text") == "Clean Text"
    # Strip HTML tags
    assert sanitize("<p>Hello <b>World</b></p>") == "Hello World"
    # Neutralize javascript: protocols
    assert sanitize("javascript:alert(1)") == "unsafe-protocol:alert(1)"
    assert sanitize("JAVASCRIPT:alert(1)") == "unsafe-protocol:alert(1)"

def test_sanitize_sqli_attacks():
    # Escape single quotes
    assert sanitize("admin' OR '1'='1") == "admin'' OR ''1''=''1"
    # Neutralize comment characters
    assert sanitize("SELECT * FROM users; -- comment") == "SELECT * FROM users;  - -  comment"
    assert sanitize("SELECT /*+ HINT */ * FROM users") == "SELECT  / * + HINT  * /  * FROM users"

def test_sanitize_nosqli_attacks():
    # Recursive dictionary strip for keys starting with $
    payload = {
        "username": "admin",
        "password": {"$ne": "pwd"},
        "nested": {
            "valid": "ok",
            "$gt": 10
        }
    }
    expected = {
        "username": "admin",
        "password": {},
        "nested": {
            "valid": "ok"
        }
    }
    assert sanitize(payload) == expected

def test_sanitize_recursive_lists():
    payload = ["admin' OR '1'='1", {"$gt": 10}, "<script>alert(1)</script>Clean"]
    expected = ["admin'' OR ''1''=''1", {}, "Clean"]
    assert sanitize(payload) == expected
