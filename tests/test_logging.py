"""
Tests for structured logging functionality.

Verifies request ID propagation, log field validation, and JSON formatting.
"""

import pytest
import json
import logging
from io import StringIO

from forgery_detection.logging_config import (
    setup_logging,
    RequestIDFilter,
    StructuredLogger,
    request_id_var,
    calculate_file_hash
)


def test_request_id_filter():
    """Test that RequestIDFilter adds request_id to log records."""
    # Set request ID
    request_id_var.set("test-request-123")
    
    # Create filter
    filter = RequestIDFilter()
    
    # Create log record
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Test message",
        args=(),
        exc_info=None
    )
    
    # Apply filter
    filter.filter(record)
    
    # Verify request ID was added
    assert hasattr(record, 'request_id')
    assert record.request_id == "test-request-123"


def test_request_id_filter_no_request():
    """Test RequestIDFilter when no request ID is set."""
    # Clear request ID
    request_id_var.set(None)
    
    filter = RequestIDFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Test message",
        args=(),
        exc_info=None
    )
    
    filter.filter(record)
    
    assert record.request_id == "no-request-id"


def test_json_logging_format():
    """Test that JSON logging produces valid JSON output."""
    # Capture log output
    log_stream = StringIO()
    handler = logging.StreamHandler(log_stream)
    
    # Setup JSON logging
    logger = setup_logging(log_level="INFO", log_format="json")
    logger.handlers.clear()
    logger.addHandler(handler)
    
    # Set request ID
    request_id_var.set("test-123")
    
    # Log a message
    logger.info("Test message", extra={"custom_field": "custom_value"})
    
    # Get log output
    log_output = log_stream.getvalue()
    
    # Verify it's valid JSON
    try:
        log_data = json.loads(log_output.strip())
        assert log_data["message"] == "Test message"
        assert log_data["level"] == "INFO"
        assert "timestamp" in log_data
    except json.JSONDecodeError:
        pytest.fail("Log output is not valid JSON")


def test_structured_logger():
    """Test StructuredLogger wrapper functionality."""
    logger = StructuredLogger("test_logger")
    
    # Set request ID
    request_id_var.set("struct-test-456")
    
    # Test different log levels
    logger.info("Info message", test_field="test_value")
    logger.warning("Warning message", warning_code=123)
    logger.error("Error message", error_type="TestError")
    logger.debug("Debug message", debug_info="details")
    
    # No assertions needed - just verify no exceptions


def test_log_request_method():
    """Test StructuredLogger.log_request method."""
    logger = StructuredLogger("test_logger")
    request_id_var.set("req-789")
    
    # Should not raise exception
    logger.log_request(
        pdf_filename="test.pdf",
        file_size=1024,
        file_hash="abc123",
        client_ip="127.0.0.1"
    )


def test_log_response_method():
    """Test StructuredLogger.log_response method."""
    logger = StructuredLogger("test_logger")
    request_id_var.set("resp-101")
    
    logger.log_response(
        pdf_filename="test.pdf",
        status="No Suspicion",
        total_points=0,
        duration=1.234
    )


def test_log_error_method():
    """Test StructuredLogger.log_error method."""
    logger = StructuredLogger("test_logger")
    request_id_var.set("err-202")
    
    logger.log_error(
        pdf_filename="test.pdf",
        error="Test error message",
        error_type="ValidationError"
    )


def test_calculate_file_hash():
    """Test file hash calculation."""
    test_data = b"Test PDF content"
    hash_result = calculate_file_hash(test_data)
    
    # Verify it's a valid SHA-256 hash (64 hex characters)
    assert len(hash_result) == 64
    assert all(c in '0123456789abcdef' for c in hash_result)
    
    # Verify consistency
    hash_result2 = calculate_file_hash(test_data)
    assert hash_result == hash_result2
    
    # Verify different data produces different hash
    different_data = b"Different content"
    different_hash = calculate_file_hash(different_data)
    assert hash_result != different_hash


@pytest.mark.asyncio
async def test_request_id_middleware(client, sample_pdf):
    """Test that RequestIDMiddleware adds X-Request-ID header."""
    with open(sample_pdf, 'rb') as f:
        pdf_data = f.read()
    
    files = {"file": ("test.pdf", pdf_data, "application/pdf")}
    response = await client.post("/forgery-check", files=files)
    
    # Verify X-Request-ID header is present
    assert "X-Request-ID" in response.headers
    request_id = response.headers["X-Request-ID"]
    
    # Verify it's a valid UUID format (36 characters with hyphens)
    assert len(request_id) == 36
    assert request_id.count('-') == 4


@pytest.mark.asyncio
async def test_request_id_uniqueness_across_requests(client, sample_pdf):
    """Test that each request gets a unique request ID."""
    with open(sample_pdf, 'rb') as f:
        pdf_data = f.read()
    
    request_ids = set()
    
    # Make 10 sequential requests
    for i in range(10):
        files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
        response = await client.post("/forgery-check", files=files)
        
        if response.status_code == 200:
            request_id = response.headers.get("X-Request-ID")
            request_ids.add(request_id)
    
    # All request IDs should be unique
    assert len(request_ids) == 10
