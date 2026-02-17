"""
PDF Forgery Detection API

A comprehensive API for detecting forgery indicators in PDF documents.
"""

from forgery_detection.models import ForgeryStatus, OverlapInfo, PageDeletionInfo
from forgery_detection.checker import PDFForgeryChecker

__version__ = "2.0.0"
__all__ = ["ForgeryStatus", "OverlapInfo", "PageDeletionInfo", "PDFForgeryChecker"]
