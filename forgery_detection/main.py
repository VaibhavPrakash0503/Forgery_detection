"""
Main entry point for PDF Forgery Detection API.
"""

import uvicorn
import logging

from config import DEFAULT_CONFIG
from forgery_detection.api import app
from forgery_detection.logging_config import setup_logging

# Setup logging
logger = setup_logging(
    log_level=DEFAULT_CONFIG.log_level if hasattr(DEFAULT_CONFIG, 'log_level') else "INFO",
    log_format="json"
)


@app.on_event("startup")
async def startup_event():
    """Log startup message."""
    logger.info("PDF Forgery Detection API v2.0.0 starting up")


@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown message."""
    logger.info("PDF Forgery Detection API shutting down")


if __name__ == "__main__":
    logger.info("Starting PDF Forgery Detection API v2.0.0")
    uvicorn.run(
        "forgery_detection.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_config=None  # Use our custom logging config
    )
