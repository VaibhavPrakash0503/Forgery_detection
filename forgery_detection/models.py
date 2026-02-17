"""
Pydantic models for PDF forgery detection API.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class OverlapInfo(BaseModel):
    pages_with_overlaps: List[int] = Field(default_factory=list)
    total_overlaps: int = 0
    warning: Optional[str] = None
    content: Dict[str, Any] = Field(default_factory=dict)


class PageDeletionInfo(BaseModel):
    """Detailed information about suspected page deletions."""
    has_deletions: bool = False
    current_page_count: int = 0
    missing_object_count: int = 0
    gap_pattern: str = Field(
        default="",
        description="Analysis of object ID gap patterns (regular vs irregular)"
    )


class ForgeryStatus(BaseModel):
    status: str = Field(
        description="Forgery assessment status: 'Suspicious', 'Might be Suspicious', or 'No Suspicion'"
    )
    suspicion_level: str = Field(
        description="Level of suspicion: None, Moderate, or High"
    )
    flagged_functions: List[str] = Field(
        default_factory=list,
        description="List of functions that detected suspicious activity",
    )
    total_points: int = Field(
        default=0, description="Total suspicion points calculated"
    )
    explanation: Optional[str] = Field(
        None, description="Detailed explanation of findings"
    )
    overlap_details: Optional[OverlapInfo] = Field(
        None, description="Detailed information about text overlaps"
    )
    timestamp: str = Field(description="Analysis timestamp")
    filename: str = Field(description="Name of analyzed file")
    explanations: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Detailed explanations for each flagged function",
    )
    observations: Optional[List[str]] = Field(
        default_factory=list,
        description="Observational warnings and notes not contributing to suspicion points",
    )
    page_deletion_details: Optional[PageDeletionInfo] = Field(
        None, description="Detailed page deletion analysis if deletions detected"
    )
