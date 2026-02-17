"""
Configuration management for PDF Forgery Detection API.

This module centralizes all detection thresholds and configuration parameters,
making the system easier to tune and maintain.
"""

from dataclasses import dataclass
from typing import Optional
import os


@dataclass
class ForgeryDetectionConfig:
    """Configuration for forgery detection thresholds and parameters."""
    
    # Metadata checks
    metadata_missing_both_dates: int = 3
    metadata_missing_creation: int = 2
    metadata_missing_modification: int = 1
    metadata_identical_dates: int = 0  # Observational only - common in legitimate PDFs
    
    # Object density thresholds
    object_density_extreme: int = 500
    object_density_very_high: int = 300
    object_density_high: int = 200  # Raised threshold - complex documents are legitimate
    object_density_suspicious_multiplier: int = 3
    
    # Page deletion detection
    page_deletion_xref_points: int = 4
    page_deletion_gaps_points: int = 5
    page_gap_threshold: float = 0.15  # 15% gaps - some tools create gaps
    page_structure_missing_pages: int = 5
    page_structure_mismatch: int = 2
    
    # Incremental updates
    incremental_updates_threshold: int = 3
    incremental_updates_excessive: int = 5
    incremental_updates_suspicious: int = 7
    incremental_updates_normal: int = 4
    
    # Embedded content
    embedded_files_scripts_points: int = 6
    
    # Image overlap
    image_overlap_points: int = 3
    
    # Font analysis
    rare_font_usage_threshold: float = 0.05  # 5%
    rare_font_max_count: int = 3
    rare_font_min_pages: int = 5
    rare_font_points: int = 2
    unique_font_points: int = 1
    high_font_diversity_threshold: int = 5
    
    # Object order
    object_order_significant_threshold: float = 0.3  # 30%
    object_order_minor_threshold: float = 0.1  # 10%
    object_order_significant_points: int = 2
    object_order_minor_points: int = 1
    
    # Annotations and forms
    annotations_forms_points: int = 1
    
    # Layers
    layers_points: int = 1
    
    # Text overlap detection
    text_overlap_min_area_ratio: float = 0.1  # 10%
    text_overlap_min_length: int = 15
    text_overlap_similarity_threshold: float = 0.8
    text_overlap_common_substring_min: int = 10
    text_overlap_points: int = 2
    
    # Text modification detection
    text_mod_rare_font_percentage: float = 5.0
    text_mod_rare_font_max_usage: int = 3
    text_mod_high_diversity_fonts: int = 5
    text_mod_dominant_ratio: float = 0.1
    text_mod_min_outliers: int = 2
    text_mod_points_per_page: int = 2
    text_mod_max_points: int = 8
    
    # Character spacing analysis (new)
    char_spacing_variance_multiplier: float = 2.0
    char_spacing_points: int = 3
    
    # Baseline alignment (new)
    baseline_outlier_threshold: float = 0.5
    baseline_outlier_percentage: float = 0.4  # 40% - modern PDFs use flexible layouts
    baseline_min_lines: int = 5
    baseline_points: int = 0  # Observational only - modern PDFs naturally have varied layouts
    
    # Digital signatures (new)
    signature_missing_points: int = 1
    
    # Content stream anomalies (new)
    content_stream_position_ratio: float = 0.5
    content_stream_points: int = 5
    
    # Page labels (new)
    page_labels_gap_points: int = 6
    
    # Suspicion level thresholds
    suspicion_high_threshold: int = 7
    suspicion_moderate_min: int = 4
    suspicion_moderate_max: int = 6
    
    # API security
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    
    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "json"  # json or text
    log_file: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> "ForgeryDetectionConfig":
        """
        Create configuration from environment variables.
        
        Environment variables should be prefixed with FORGERY_DETECT_
        Example: FORGERY_DETECT_MAX_FILE_SIZE=104857600
        """
        config = cls()
        
        # Override with environment variables if present
        if max_size := os.getenv("FORGERY_DETECT_MAX_FILE_SIZE"):
            config.max_file_size = int(max_size)
        
        if rate_limit := os.getenv("FORGERY_DETECT_RATE_LIMIT"):
            config.rate_limit = rate_limit
        
        if high_threshold := os.getenv("FORGERY_DETECT_HIGH_THRESHOLD"):
            config.suspicion_high_threshold = int(high_threshold)
        
        return config


# Default configuration instance
DEFAULT_CONFIG = ForgeryDetectionConfig()
