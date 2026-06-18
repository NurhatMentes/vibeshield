import re
import pytest
from src.errors import handle_exception, generate_tracking_id
from src.stack_sanitizer import sanitize_traceback


# ==========================================
# 1. STACK TRACE SANITIZER UNIT TESTS
# ==========================================
class TestStackSanitizer:
    def test_redact_unix_home_paths(self):
        dirty = "Error: ENOENT at /home/user/secret/db_password.py:42"
        clean = sanitize_traceback(dirty)
        assert "/home/user/secret/db_password" not in clean
        assert "[PROJECT_ROOT]/..." in clean

    def test_redact_macos_paths(self):
        dirty = "TypeError at /Users/nurhat/projects/vibeshield/src/db.py:15"
        clean = sanitize_traceback(dirty)
        assert "/Users/nurhat" not in clean
        assert "[PROJECT_ROOT]/..." in clean

    def test_redact_windows_paths(self):
        dirty = "Error at C:\\Users\\nurha\\Desktop\\Uygulamalar\\VibeShield\\src\\index.py:10"
        clean = sanitize_traceback(dirty)
        assert "C:\\Users\\nurha" not in clean
        assert "[PROJECT_ROOT]/..." in clean

    def test_redact_venv_paths(self):
        dirty = "File .venv/lib/python3.12/site-packages/fastapi/routing.py:123"
        clean = sanitize_traceback(dirty)
        assert ".venv/lib" not in clean
        assert "[PYTHON_ENV]/..." in clean

    def test_redact_site_packages_paths(self):
        dirty = "File site-packages/starlette/middleware.py:45"
        clean = sanitize_traceback(dirty)
        assert "site-packages/starlette" not in clean
        assert "[PYTHON_ENV]/..." in clean

    def test_redact_ipv4_addresses(self):
        dirty = "Connection refused to 192.168.1.100:5432"
        clean = sanitize_traceback(dirty)
        assert "192.168.1.100" not in clean
        assert "[REDACTED_IP]" in clean

    def test_redact_ipv6_addresses(self):
        dirty = "Listening on 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        clean = sanitize_traceback(dirty)
        assert "2001:0db8" not in clean
        assert "[REDACTED_IP]" in clean

    def test_redact_postgres_connection_string(self):
        dirty = "Failed to connect: postgres://admin:p4ssw0rd@db.internal.io:5432/production_db"
        clean = sanitize_traceback(dirty)
        assert "postgres://" not in clean
        assert "p4ssw0rd" not in clean
        assert "production_db" not in clean
        assert "[REDACTED_DB_INFO]" in clean

    def test_redact_mongodb_connection_string(self):
        dirty = "MongoError: mongodb+srv://root:secret@cluster0.abc123.mongodb.net/mydb"
        clean = sanitize_traceback(dirty)
        assert "mongodb+srv://" not in clean
        assert "secret" not in clean
        assert "[REDACTED_DB_INFO]" in clean

    def test_redact_redis_connection_string(self):
        dirty = "RedisError: redis://default:authpass@redis.cloud:6380/0"
        clean = sanitize_traceback(dirty)
        assert "redis://" not in clean
        assert "authpass" not in clean
        assert "[REDACTED_DB_INFO]" in clean

    def test_redact_sql_table_references(self):
        dirty = 'Error: relation does not exist. SELECT * FROM users_payment_info'
        clean = sanitize_traceback(dirty)
        assert "[REDACTED_DB_INFO]" in clean

    def test_handles_exception_objects(self):
        try:
            raise RuntimeError("Crash at /home/user/secret/db_password with IP 192.168.1.100")
        except Exception as exc:
            clean = sanitize_traceback(exc)
            assert "/home/user/secret" not in clean
            assert "192.168.1.100" not in clean
            assert "[PROJECT_ROOT]/..." in clean
            assert "[REDACTED_IP]" in clean

    def test_complex_multiline_stack_trace(self):
        dirty = "\n".join([
            'Error: FATAL: password authentication failed for user "admin"',
            '    at Connection.parseE (/home/deploy/app/node_modules/pg/lib/client.py:95)',
            '    at Connection._handleCommandComplete (C:\\Users\\nurha\\Projects\\api\\src\\db.py:42)',
            '    at TLSSocket.<anonymous> (192.168.1.50:5432)',
            '  Connection string: postgres://admin:s3cret@10.0.0.5:5432/prod_orders',
        ])
        clean = sanitize_traceback(dirty)
        assert "/home/deploy" not in clean
        assert "C:\\Users\\nurha" not in clean
        assert "192.168.1.50" not in clean
        assert "10.0.0.5" not in clean
        assert "postgres://" not in clean
        assert "s3cret" not in clean

    def test_redacts_container_paths(self):
        stack = 'Error at /app/src/index.py:10'
        clean = sanitize_traceback(stack)
        assert '[PROJECT_ROOT]/...' in clean
        assert '/app/' not in clean

    def test_redacts_kubernetes_paths(self):
        stack = 'Error at /srv/app/dist/bundle.py:1'
        clean = sanitize_traceback(stack)
        assert '[PROJECT_ROOT]/...' in clean
        assert '/srv/' not in clean


# ==========================================
# 2. ERROR HANDLER INTEGRATION TESTS
# ==========================================
class TestErrorHandler:
    def test_generate_tracking_id_format(self):
        tid = generate_tracking_id()
        assert re.match(r"^VS-[A-Z0-9]{4}$", tid)

    def test_handle_exception_masks_sensitive_data(self):
        try:
            raise ValueError("Sensitive database connection lost!")
        except Exception as e:
            payload, tracking_id = handle_exception(e)

            assert re.match(r"^VS-[A-Z0-9]{4}$", tracking_id)
            assert payload["tracking_id"] == tracking_id
            assert payload["success"] is False
            assert "Sensitive database connection" not in payload["message"]
            assert payload["message"] == "Internal Server Error"

    def test_handle_exception_logs_sanitized_trace(self, caplog):
        try:
            raise RuntimeError("Crash at /home/user/secret/db with IP 192.168.1.100")
        except Exception as e:
            with caplog.at_level("ERROR", logger="VibeShield"):
                handle_exception(e)
            
            log_output = caplog.text
            assert "Unhandled Exception Captured" in log_output
            assert "/home/user/secret" not in log_output
            assert "192.168.1.100" not in log_output
