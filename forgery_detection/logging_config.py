"""
Structured logging configuration for PDF forgery detection API.

Provides request ID tracking, JSON formatting, and performance monitoring.
"""

import logging
import time
import hashlib
import uuid
from contextvars import ContextVar
from typing import Optional
from functools import wraps

from pythonjsonlogger import jsonlogger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# Context variable for request ID (thread-safe)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


class RequestIDFilter(logging.Filter):
    """Add request ID to log records."""
    
    def filter(self, record):
        record.request_id = request_id_var.get() or "no-request-id"
        return True


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to generate and track request IDs."""
    
    async def dispatch(self, request: Request, call_next):
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request_id_var.set(request_id)
        
        # Add to request state for access in routes
        request.state.request_id = request_id
        
        # Add to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        
        return response


def setup_logging(log_level: str = "INFO", log_format: str = "json"):
    """
    Configure structured logging.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_format: Format type ('json' or 'text')
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Create console handler
    handler = logging.StreamHandler()
    
    if log_format == "json":
        # JSON formatter with custom fields
        formatter = jsonlogger.JsonFormatter(
            fmt="%(asctime)s %(name)s %(levelname)s %(request_id)s %(message)s",
            rename_fields={
                "asctime": "timestamp",
                "levelname": "level",
                "name": "logger"
            }
        )
    else:
        # Text formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    handler.setFormatter(formatter)
    handler.addFilter(RequestIDFilter())
    logger.addHandler(handler)
    
    return logger


def calculate_file_hash(data: bytes) -> str:
    """Calculate SHA-256 hash of file data."""
    return hashlib.sha256(data).hexdigest()


def log_performance(logger: logging.Logger):
    """
    Decorator to log function execution time.
    
    Usage:
        @log_performance(logger)
        def my_function():
            pass
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                logger.info(
                    f"{func.__name__} completed",
                    extra={
                        "function": func.__name__,
                        "duration_seconds": round(duration, 3),
                        "status": "success"
                    }
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"{func.__name__} failed",
                    extra={
                        "function": func.__name__,
                        "duration_seconds": round(duration, 3),
                        "status": "error",
                        "error": str(e)
                    },
                    exc_info=True
                )
                raise
        return wrapper
    return decorator


class StructuredLogger:
    """Wrapper for structured logging with common fields."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def _log(self, level: str, message: str, **kwargs):
        """Internal log method with structured fields."""
        getattr(self.logger, level)(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        self._log("info", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log("warning", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log("error", message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self._log("debug", message, **kwargs)
    
    def log_request(self, pdf_filename: str, file_size: int, file_hash: str, client_ip: str):
        """Log incoming request with structured fields."""
        self.info(
            "PDF analysis request received",
            event="request_received",
            pdf_filename=pdf_filename,
            file_size_bytes=file_size,
            file_hash=file_hash,
            client_ip=client_ip
        )
    
    def log_response(self, pdf_filename: str, status: str, total_points: int, duration: float):
        """Log analysis response with structured fields."""
        self.info(
            "PDF analysis completed",
            event="analysis_completed",
            pdf_filename=pdf_filename,
            forgery_status=status,
            suspicion_points=total_points,
            duration_seconds=round(duration, 3)
        )
    
    def log_error(self, pdf_filename: str, error: str, error_type: str):
        """Log error with structured fields."""
        self.error(
            "PDF analysis failed",
            event="analysis_failed",
            pdf_filename=pdf_filename,
            error_message=error,
            error_type=error_type
        )
