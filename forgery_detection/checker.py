"""
PDF Forgery Checker - Core detection logic.

Contains the PDFForgeryChecker class with all forgery detection methods.
"""

import logging
from typing import Tuple, Optional, List, Dict, Any
from datetime import datetime
import fitz  # PyMuPDF
from PyPDF2 import PdfReader
from pdfminer.high_level import extract_text

from config import ForgeryDetectionConfig, DEFAULT_CONFIG
from forgery_detection.models import OverlapInfo, PageDeletionInfo, ForgeryStatus

logger = logging.getLogger(__name__)


class PDFForgeryChecker:
    """Main class for detecting forgery indicators in PDF documents."""
    
    def __init__(self, pdf_path: str, config: Optional[ForgeryDetectionConfig] = None):
        """
        Initialize PDF forgery checker.
        
        Args:
            pdf_path: Path to the PDF file to analyze
            config: Optional configuration object for detection thresholds
        """
        self.pdf_path = pdf_path
        self.reader = PdfReader(pdf_path)
        self.doc = fitz.open(pdf_path)
        self.config = config or DEFAULT_CONFIG
        
        # Initialize raw_data for incremental updates check
        with open(pdf_path, 'rb') as f:
            self.raw_data = f.read()
        
        logger.info(f"Initialized forgery checker for: {pdf_path}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure resources are cleaned up."""
        self.close()
        return False  # Don't suppress exceptions

    def format_pdf_date(self, pdf_date: str) -> str:
        """Format PDF date string to DD/MM/YYYY HH:MM format"""
        if not pdf_date or not pdf_date.startswith("D:"):
            return "Not available"
        try:
            clean_date = pdf_date[2:]  # Remove "D:"
            # Extract the basic format (YYYYMMDDHHMMSS)
            date_part = clean_date[:14]
            parsed = datetime.strptime(date_part, "%Y%m%d%H%M%S")
            return parsed.strftime("%d/%m/%Y %H:%M")
        except Exception:
            return "Invalid date format"

    def check_metadata(self) -> Tuple[int, Optional[str]]:
        try:
            metadata = self.reader.metadata
            if not metadata:
                return 0, None

            creation = metadata.get("/CreationDate", "N/A")
            mod = metadata.get("/ModDate", "N/A")

            # Both dates missing
            if creation == "N/A" and mod == "N/A":
                return 3, "No creation and modification dates"

            # Only creation date missing
            if creation == "N/A" and mod != "N/A":
                return 2, "No creation date"

            # Only modification date missing
            if creation != "N/A" and mod == "N/A":
                return 1, "No modification date"

            # Both dates exist - check if they're identical
            if creation != "N/A" and mod != "N/A":
                # Compare first 14 chars (YYYYMMDDHHmmss) - exact same timestamp
                if creation[:14] == mod[:14]:
                    return 0, "identical_dates"  # Observational - common in legitimate PDFs

            # Both dates exist and different (normal)
            return 0, None

        except Exception:
            return 0, None

    def check_page_deletion(self) -> Tuple[int, Optional[str]]:
        try:
            suspicion = 0
            messages = []

            # Get actual page count
            actual_page_count = len(self.reader.pages)

            # Check XRef table for freed/deleted objects
            if hasattr(self.reader, "xref"):
                deleted_objects = 0
                for entry in self.reader.xref.values():
                    if (
                        hasattr(entry, "type") and entry.type == 0
                    ):  # Type 0 = freed object
                        deleted_objects += 1

                if deleted_objects > 0:
                    suspicion += 4
                    messages.append(
                        f"Found {deleted_objects} deleted objects in XRef table"
                    )

            # Check for gaps in page object numbers
            page_objects = []
            for page in self.reader.pages:
                if hasattr(page, "indirect_reference"):
                    page_objects.append(page.indirect_reference.idnum)

            if page_objects:
                page_objects.sort()
                gaps = sum(
                    1
                    for i in range(len(page_objects) - 1)
                    if page_objects[i + 1] - page_objects[i] > 1
                )
                if gaps > actual_page_count * 0.05:  # More than 5% gaps
                    suspicion += 5
                    messages.append(
                        f"Unusual gaps in page object numbering ({gaps} gaps)"
                    )

            message = "; ".join(messages) if messages else None
            return suspicion, message

        except Exception as e:
            return 0, f"Error checking page deletion: {str(e)}"

    def check_page_structure(self) -> Tuple[int, Optional[str]]:
        try:
            # Get trailer safely
            trailer = self.reader.trailer
            if not isinstance(trailer, dict):
                return 2, "invalid_trailer"

            # Get root object
            root = trailer.get("/Root")
            if not root:
                return 2, "missing_root"

            # Dereference if indirect object
            if hasattr(root, "get_object"):
                root = root.get_object()

            # Ensure root is dictionary-like
            if not isinstance(root, dict):
                return 2, "invalid_root_object"

            # Get pages object
            pages = root.get("/Pages")
            if not pages:
                return 2, "missing_pages_entry"

            # Dereference pages if needed
            if hasattr(pages, "get_object"):
                pages = pages.get_object()

            # Get declared count safely
            declared_count = None
            if isinstance(pages, dict):
                declared_count = pages.get("/Count")

            actual_count = len(self.reader.pages)

            if declared_count is None:
                return 2, "missing_page_count"
            elif declared_count != actual_count:
                # Additional check for deleted pages
                if declared_count > actual_count:
                    return 5, "pages_missing"
                return 2, "page_count_mismatch"
            return 0, None

        except Exception:
            return 2, "page_structure_error"

    def inspect_object_density(self) -> Tuple[int, Optional[str]]:
        try:
            total_objects = self.doc.xref_length()
            num_pages = len(self.doc)
            if num_pages == 0:
                return 0, None

            obj_per_page = total_objects / num_pages

            # Analyze VISIBLE content to calculate expected baseline
            suspicious_indicators = 0

            # Sample first page to estimate expected objects
            if num_pages > 0:
                sample_page = self.doc[0]

                images = len(sample_page.get_images())
                links = len(sample_page.get_links())

                # Get text blocks properly
                page_dict = sample_page.get_text("dict")
                text_blocks = (
                    len(page_dict.get("blocks", []))
                    if isinstance(page_dict, dict)
                    else 0
                )

                # Calculate expected objects based on visible content
                expected_objs = (
                    images * 5  # Images with masks/filters = ~5 objects
                    + links * 4  # Links/annotations = ~4 objects
                    + text_blocks * 2  # Text blocks = ~2 objects
                    + 15  # Base (page structure, fonts, resources)
                )

                # Only flag if SIGNIFICANTLY exceeds expected
                if obj_per_page > expected_objs * 3:  # 3x more than expected
                    suspicious_indicators += 1

            # MUCH higher thresholds for absolute density
            if obj_per_page > 500:  # Extremely abnormal
                return 8, "extremely_high_object_density"
            elif obj_per_page > 300:  # Very unusual
                return 6, "very_high_object_density"
            elif obj_per_page > 150 and suspicious_indicators > 0:
                # High density AND unexplained objects
                return 5, "suspicious_object_density"
            elif obj_per_page > 200:
                # High but might be legitimate (complex forms/graphics)
                return 3, "high_object_density"

            return 0, None
        except Exception:
            return 0, None

    def detect_hidden_content(self) -> Tuple[int, Optional[str]]:
        try:
            text = extract_text(self.pdf_path)
            if not text.strip():
                return 2, "hidden_content"
            return 0, None
        except Exception:
            return 0, "text_extraction_failed"

    def check_incremental_updates(self) -> Tuple[int, Optional[str]]:
        try:
            eof_count = self.raw_data.count(b"%%EOF")

            # Check for suspicious patterns, not just multiple EOFs
            # Multiple updates are normal, but check for anomalies
            if eof_count > 3:  # More lenient threshold
                # Additional checks for truly suspicious updates
                xref_count = self.raw_data.count(b"xref")
                trailer_count = self.raw_data.count(b"trailer")

                # If xref/trailer counts don't match EOF, something's wrong
                if (
                    abs(xref_count - eof_count) > 1
                    or abs(trailer_count - eof_count) > 1
                ):
                    return 7, "suspicious_incremental_updates"

                # Many updates but structure seems ok - lower score
                if eof_count > 5:
                    return 4, "excessive_incremental_updates"

            return 0, None
        except Exception:
            return 0, None

    def check_embedded_files_scripts(self) -> Tuple[int, Optional[str]]:
        try:
            root = self.reader.trailer["/Root"]
            if hasattr(root, "get_object"):
                root = root.get_object()

            names = root.get("/Names") if isinstance(root, dict) else None
            if names and hasattr(names, "get_object"):
                names = names.get_object()

            has_embedded = isinstance(names, dict) and "/EmbeddedFiles" in names

            has_js = False
            if isinstance(root, dict) and "/OpenAction" in root:
                try:
                    action = root["/OpenAction"]
                    if hasattr(action, "get_object"):
                        action = action.get_object()

                    if isinstance(action, dict) and (
                        action.get("/S") == "/JavaScript" or "/JS" in action
                    ):
                        has_js = True
                except Exception:
                    pass

            if has_embedded or has_js:
                return 6, "embedded_files_scripts"
            return 0, None
        except Exception:
            return 0, None

    def detect_overlapping_text(self) -> OverlapInfo:
        try:
            pages_with_overlaps = []
            total_overlaps = 0
            page_overlap_content = {}

            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                blocks = page.get_text("dict").get("blocks", [])

                # Validate blocks have text content
                text_blocks = [
                    (fitz.Rect(b["bbox"]), b)
                    for b in blocks
                    if b.get("type") == 0 and b.get("lines")  # Check has text
                ]

                overlaps_data = []
                seen_pairs = set()  # Track processed pairs

                for i, (r1, b1) in enumerate(text_blocks):
                    for j, (r2, b2) in enumerate(text_blocks[i + 1 :], i + 1):
                        pair_key = (i, j)
                        if pair_key in seen_pairs:
                            continue

                        if r1.intersects(r2):
                            intersection = r1 & r2
                            # Make threshold relative to smaller block
                            min_area = min(r1.get_area(), r2.get_area())
                            if intersection.get_area() > min_area * 0.1:  # 10% overlap
                                text1 = self._extract_text_from_block(b1)
                                text2 = self._extract_text_from_block(b2)
                                if (
                                    text1 and text2 and text1 != text2
                                ):  # Avoid duplicates
                                    overlap_result = self._find_overlapping_text(
                                        text1, text2
                                    )
                                    if overlap_result:
                                        overlaps_data.append(overlap_result)
                                        seen_pairs.add(pair_key)

                if overlaps_data:
                    pages_with_overlaps.append(page_num + 1)
                    page_overlap_content[str(page_num + 1)] = overlaps_data
                    total_overlaps += len(overlaps_data)

            warning = None
            if pages_with_overlaps:
                warning = (
                    f"Overlapping text blocks found on pages: {pages_with_overlaps}"
                )

            return OverlapInfo(
                pages_with_overlaps=pages_with_overlaps,
                total_overlaps=total_overlaps,
                warning=warning,
                content=page_overlap_content,
            )
        except Exception as e:
            return OverlapInfo(warning=f"Text overlap detection failed: {str(e)}")

    def _extract_text_from_block(self, block: dict) -> str:
        try:
            lines = block.get("lines", [])
            text_parts = []
            for line in lines:
                if "spans" in line:
                    line_text = "".join(span.get("text", "") for span in line["spans"])
                    if line_text.strip():
                        text_parts.append(line_text.strip())
            return "\n".join(text_parts)
        except Exception:
            return ""

    def _find_overlapping_text(self, text1: str, text2: str) -> Optional[List[str]]:
        try:
            overlapping_parts = []
            sentences1 = [
                s.strip() for s in text1.replace("\n", " ").split(".") if s.strip()
            ]
            sentences2 = [
                s.strip() for s in text2.replace("\n", " ").split(".") if s.strip()
            ]

            for s1 in sentences1:
                for s2 in sentences2:
                    if len(s1) > 10 and s1 in s2:
                        overlapping_parts.append(s1)
                    elif len(s2) > 10 and s2 in s1:
                        overlapping_parts.append(s2)
                    elif self._calculate_text_similarity(s1, s2) > 0.8:
                        common_part = self._extract_common_substring(s1, s2)
                        if common_part and len(common_part) > 10:
                            overlapping_parts.append(common_part)

            unique_overlaps = []
            for overlap in overlapping_parts:
                if len(overlap.strip()) > 15:
                    is_duplicate = False
                    for existing in unique_overlaps:
                        if overlap in existing or existing in overlap:
                            if len(overlap) > len(existing):
                                unique_overlaps.remove(existing)
                            else:
                                is_duplicate = True
                            break
                    if not is_duplicate:
                        unique_overlaps.append(overlap.strip())
            return unique_overlaps if unique_overlaps else None
        except Exception:
            return None

    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        try:
            words1 = set(text1.lower().split())
            words2 = set(text2.lower().split())
            if not words1 or not words2:
                return 0.0
            intersection = words1.intersection(words2)
            union = words1.union(words2)
            return len(intersection) / len(union) if union else 0.0
        except Exception:
            return 0.0

    def _extract_common_substring(self, text1: str, text2: str) -> str:
        try:
            m, n = len(text1), len(text2)
            dp = [[0] * (n + 1) for _ in range(m + 1)]
            longest = 0
            ending_pos = 0

            for i in range(1, m + 1):
                for j in range(1, n + 1):
                    if text1[i - 1].lower() == text2[j - 1].lower():
                        dp[i][j] = dp[i - 1][j - 1] + 1
                        if dp[i][j] > longest:
                            longest = dp[i][j]
                            ending_pos = i
                    else:
                        dp[i][j] = 0

            if longest > 10:
                return text1[ending_pos - longest : ending_pos].strip()
            return ""
        except Exception:
            return ""

    def check_image_overlap(self) -> Tuple[int, Optional[str]]:
        try:
            for page in self.doc:
                images = page.get_images(full=True)
                if len(images) < 2:
                    continue

                rects = []
                for img in images:
                    try:
                        rect = fitz.Rect(img[1:5])
                        rects.append(rect)
                    except Exception:
                        continue

                for i, r1 in enumerate(rects):
                    for r2 in rects[i + 1 :]:
                        if r1.intersects(r2):
                            return 3, "image_overlap_detected"
            return 0, None
        except Exception:
            return 0, None

    def check_fonts(self) -> Tuple[int, Optional[str]]:
        try:
            font_sets = []
            font_counts = {}

            for page in self.doc:
                fonts = [font[3] for font in page.get_fonts()]
                font_sets.append(frozenset(fonts))
                for font in fonts:
                    font_counts[font] = font_counts.get(font, 0) + 1

            # Check for rare fonts (used on only 1-2 pages)
            rare_fonts = [
                f
                for f, count in font_counts.items()
                if count <= 2 and len(self.doc) > 5
            ]

            if rare_fonts and len(rare_fonts) > 2:
                return (
                    2,
                    f"Suspicious rare fonts found: {len(rare_fonts)} fonts used on ≤2 pages",
                )

            # Check if one page has dramatically different fonts
            if len(font_sets) > 1:
                font_set_counts = {}
                for fs in font_sets:
                    key = frozenset(fs)
                    font_set_counts[key] = font_set_counts.get(key, 0) + 1

                # If one page has unique font set
                unique_pages = sum(
                    1 for count in font_set_counts.values() if count == 1
                )
                if unique_pages > 0 and len(self.doc) > 3:
                    return 1, f"{unique_pages} page(s) with unique font combinations"

            return 0, None
        except Exception:
            return 0, None

    def check_object_order(self) -> Tuple[int, Optional[str]]:
        try:
            ids = []
            for page in self.reader.pages:
                if hasattr(page, "indirect_reference") and page.indirect_reference:
                    ids.append(page.indirect_reference.idnum)

            if not ids:
                return 0, None

            # Check for reversed or significantly scrambled order
            sorted_ids = sorted(ids)

            # Calculate how many positions are "wrong"
            mismatches = sum(1 for i, id in enumerate(ids) if id != sorted_ids[i])
            mismatch_ratio = mismatches / len(ids)

            # Only flag if significantly disordered (>30% out of order)
            if mismatch_ratio > 0.3:
                return (
                    2,
                    f"Page objects significantly out of order ({int(mismatch_ratio * 100)}% mismatched)",
                )
            elif mismatch_ratio > 0.1:
                return (
                    1,
                    f"Some page object disorder detected ({int(mismatch_ratio * 100)}% mismatched)",
                )

            return 0, None
        except Exception:
            return 0, None

    def check_annotations_and_forms(self) -> Tuple[int, Optional[str]]:
        try:
            has_annotations = False
            for page in self.reader.pages:
                if "/Annots" in page and page["/Annots"]:
                    has_annotations = True
                    break

            has_forms = "/AcroForm" in self.reader.trailer["/Root"]

            if has_annotations or has_forms:
                return 1, "annotations_or_forms"
            return 0, None
        except Exception:
            return 0, None

    def check_layers(self) -> Tuple[int, Optional[str]]:
        try:
            if "/OCProperties" in self.reader.trailer["/Root"]:
                return 1, "layers_detected"
            return 0, None
        except Exception:
            return 0, None

    def close(self):
        try:
            self.doc.close()
        except Exception:
            pass

    def detect_text_modifications(self) -> Tuple[int, Optional[str]]:
        """Detect signs of text being added based on font frequency analysis"""
        try:
            suspicious_pages = []
            indicators = []

            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                blocks = page.get_text("dict").get("blocks", [])

                font_usage = {}  # Track how many times each font is used
                font_details = {}  # Track size/color for each font

                for block in blocks:
                    if block.get("type") == 0:  # Text block
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                font = span.get("font", "")
                                size = span.get("size", 0)
                                color = span.get("color", 0)

                                # Count font usage
                                if font:
                                    font_usage[font] = font_usage.get(font, 0) + 1

                                    # Store details for analysis
                                    if font not in font_details:
                                        font_details[font] = {"sizes": [], "colors": []}
                                    font_details[font]["sizes"].append(size)
                                    font_details[font]["colors"].append(color)

                if not font_usage:
                    continue

                page_suspicious = False
                total_font_instances = sum(font_usage.values())

                # Analysis 1: Rare fonts (used very few times)
                rare_fonts = []
                for font, count in font_usage.items():
                    usage_percentage = (count / total_font_instances) * 100
                    if (
                        usage_percentage < 5 and count <= 3
                    ):  # Less than 5% usage, max 3 times
                        rare_fonts.append((font, count))

                if rare_fonts:
                    page_suspicious = True
                    font_names = [
                        f"{font} (used {count}x)" for font, count in rare_fonts
                    ]
                    indicators.append(
                        f"Page {page_num + 1}: Rare font usage detected - {', '.join(font_names)}"
                    )

                # Analysis 2: Font diversity ratio
                unique_font_count = len(font_usage)
                if unique_font_count > 5:  # More than 5 different fonts on one page
                    page_suspicious = True
                    indicators.append(
                        f"Page {page_num + 1}: High font diversity ({unique_font_count} fonts)"
                    )

                # Analysis 3: Outlier fonts (dominant font vs rare fonts)
                if len(font_usage) >= 2:
                    sorted_fonts = sorted(
                        font_usage.items(), key=lambda x: x[1], reverse=True
                    )
                    dominant_font_count = sorted_fonts[0][1]

                    # Check if there's a big gap between dominant and rare fonts
                    outliers = [
                        (font, count)
                        for font, count in sorted_fonts[1:]
                        if count
                        < dominant_font_count * 0.1  # Less than 10% of dominant
                    ]

                    if len(outliers) >= 2:
                        page_suspicious = True
                        indicators.append(
                            f"Page {page_num + 1}: {len(outliers)} outlier fonts detected"
                        )

                # Analysis 4: Single-character fonts (very suspicious)
                for font, count in font_usage.items():
                    if count == 1:
                        page_suspicious = True
                        indicators.append(
                            f"Page {page_num + 1}: Font '{font}' used only once (highly suspicious)"
                        )
                        break

                # Analysis 5: Font with inconsistent properties
                for font, details in font_details.items():
                    sizes = details["sizes"]
                    colors = details["colors"]

                    # Same font but multiple sizes (sign of copy-paste from different source)
                    if len(set(sizes)) > 2 and font_usage[font] < 10:
                        page_suspicious = True
                        indicators.append(
                            f"Page {page_num + 1}: Font '{font}' has inconsistent sizes"
                        )
                        break

                if page_suspicious:
                    suspicious_pages.append(page_num + 1)

            if suspicious_pages:
                suspicion = min(
                    len(suspicious_pages) * 2, 8
                )  # 2 points per page, max 8
                unique_indicators = list(set(indicators))
                message = f"Text modifications detected on {len(suspicious_pages)} page(s): {'; '.join(unique_indicators[:3])}"
                return suspicion, message

            return 0, None

        except Exception as e:
            logger.error(f"Text modification detection failed: {str(e)}", exc_info=True)
            return 0, None

    def check_character_spacing(self) -> Tuple[int, Optional[str]]:
        """
        Detect abnormal character spacing patterns that may indicate text insertion.
        
        Analyzes spacing between text spans to identify irregularities common in
        copy-paste forgeries where text doesn't align naturally.
        """
        try:
            suspicious_pages = []
            
            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                blocks = page.get_text("dict").get("blocks", [])
                
                for block in blocks:
                    if block.get("type") == 0:  # Text block
                        for line in block.get("lines", []):
                            spans = line.get("spans", [])
                            if len(spans) < 2:
                                continue
                            
                            # Calculate spacing between characters
                            spacings = []
                            for i in range(len(spans) - 1):
                                x1_end = spans[i]["bbox"][2]
                                x2_start = spans[i+1]["bbox"][0]
                                spacing = x2_start - x1_end
                                spacings.append(spacing)
                            
                            # Check for unusual variance
                            if spacings:
                                avg_spacing = sum(spacings) / len(spacings)
                                if avg_spacing > 0:  # Avoid division by zero
                                    variance = sum((s - avg_spacing)**2 for s in spacings) / len(spacings)
                                    
                                    # High variance suggests manual text insertion
                                    if variance > avg_spacing * self.config.char_spacing_variance_multiplier:
                                        if page_num + 1 not in suspicious_pages:
                                            suspicious_pages.append(page_num + 1)
                                        break
            
            if suspicious_pages:
                return self.config.char_spacing_points, f"Irregular character spacing on pages: {suspicious_pages}"
            return 0, None
        except Exception as e:
            logger.error(f"Character spacing check failed: {str(e)}", exc_info=True)
            return 0, None

    def check_text_baseline_alignment(self) -> Tuple[int, Optional[str]]:
        """
        Detect text not aligned to consistent baselines.
        
        Misaligned text is common when adding text to scanned documents or
        when inserting text that doesn't match the original document's layout.
        """
        try:
            suspicious_pages = []
            
            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                blocks = page.get_text("dict").get("blocks", [])
                
                baselines = []
                for block in blocks:
                    if block.get("type") == 0:
                        for line in block.get("lines", []):
                            # Get y-coordinate of baseline
                            baseline_y = line["bbox"][3]
                            baselines.append(baseline_y)
                
                # Check for outliers (text not on regular grid)
                if len(baselines) > self.config.baseline_min_lines:
                    baselines.sort()
                    # Calculate common spacing
                    spacings = [baselines[i+1] - baselines[i] for i in range(len(baselines)-1)]
                    if spacings:
                        median_spacing = sorted(spacings)[len(spacings)//2]
                        
                        # Find lines that don't fit the grid
                        outliers = sum(1 for s in spacings 
                                     if abs(s - median_spacing) > median_spacing * self.config.baseline_outlier_threshold)
                        
                        if outliers > len(baselines) * self.config.baseline_outlier_percentage:
                            suspicious_pages.append(page_num + 1)
            
            if suspicious_pages:
                return 0, "baseline_misalignment"  # Observational only - too many false positives
            return 0, None
        except Exception as e:
            logger.error(f"Baseline alignment check failed: {str(e)}", exc_info=True)
            return 0, None

    def check_digital_signatures(self) -> Tuple[int, Optional[str]]:
        """
        Check for presence and validity of digital signatures.
        
        Digital signatures help verify document authenticity. Their absence
        or invalidity can be suspicious for important documents.
        """
        try:
            root = self.reader.trailer.get("/Root")
            if hasattr(root, "get_object"):
                root = root.get_object()
            
            # Check for signature fields
            acro_form = root.get("/AcroForm") if isinstance(root, dict) else None
            if acro_form and hasattr(acro_form, "get_object"):
                acro_form = acro_form.get_object()
            
            has_signature = False
            if isinstance(acro_form, dict):
                fields = acro_form.get("/Fields", [])
                if hasattr(fields, "get_object"):
                    fields = fields.get_object()
                
                for field in fields if isinstance(fields, list) else []:
                    if hasattr(field, "get_object"):
                        field = field.get_object()
                    if isinstance(field, dict) and field.get("/FT") == "/Sig":
                        has_signature = True
                        break
            
            if has_signature:
                # Document has signature - this is good (observational)
                return 0, "digital_signature_present"
            else:
                # No signature - minor suspicion for important documents
                return self.config.signature_missing_points, "no_digital_signature"
            
        except Exception as e:
            logger.error(f"Digital signature check failed: {str(e)}", exc_info=True)
            return 0, None

    def check_content_stream_anomalies(self) -> Tuple[int, Optional[str]]:
        """
        Detect suspicious patterns in PDF content streams.
        
        Analyzes raw PDF operators to find manual text positioning which
        is common in sophisticated forgeries.
        """
        try:
            suspicious_indicators = []
            
            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                
                # Get raw content stream
                try:
                    xref = page.xref
                    content_stream = self.doc.xref_stream(xref)
                    
                    if content_stream:
                        # Check for suspicious operators
                        suspicious_ops = [
                            b'Tm',  # Text matrix (manual positioning)
                            b'Td',  # Text position
                            b'TD',  # Text position with leading
                        ]
                        
                        # Count manual text positioning operations
                        manual_positions = sum(content_stream.count(op) for op in suspicious_ops)
                        
                        # Also check for text operations
                        text_ops = content_stream.count(b'Tj') + content_stream.count(b'TJ')
                        
                        # High ratio of manual positioning suggests inserted text
                        if text_ops > 0 and manual_positions / text_ops > self.config.content_stream_position_ratio:
                            suspicious_indicators.append(page_num + 1)
                except Exception:
                    continue
            
            if suspicious_indicators:
                return self.config.content_stream_points, f"Content stream anomalies on pages: {suspicious_indicators}"
            return 0, None
        except Exception as e:
            logger.error(f"Content stream check failed: {str(e)}", exc_info=True)
            return 0, None

    def check_page_labels(self) -> Tuple[int, Optional[str]]:
        """
        Check for inconsistencies in page labels/numbering.
        
        Gaps in page labels (e.g., 1, 2, 4, 5 - missing 3) can indicate
        page deletion attempts.
        """
        try:
            root = self.reader.trailer.get("/Root")
            if hasattr(root, "get_object"):
                root = root.get_object()
            
            page_labels = root.get("/PageLabels") if isinstance(root, dict) else None
            
            if page_labels:
                if hasattr(page_labels, "get_object"):
                    page_labels = page_labels.get_object()
                
                # Check if page labels suggest missing pages
                if isinstance(page_labels, dict):
                    nums = page_labels.get("/Nums", [])
                    if hasattr(nums, "get_object"):
                        nums = nums.get_object()
                    
                    # Analyze for gaps
                    if isinstance(nums, list) and len(nums) > 2:
                        # Extract page numbers
                        page_nums = [nums[i] for i in range(0, len(nums), 2)]
                        
                        # Check for gaps
                        for i in range(len(page_nums) - 1):
                            if page_nums[i+1] - page_nums[i] > 1:
                                return self.config.page_labels_gap_points, "page_label_gaps_detected"
            
            return 0, None
        except Exception as e:
            logger.error(f"Page labels check failed: {str(e)}", exc_info=True)
            return 0, None

    def analyze_page_deletions(self) -> PageDeletionInfo:
        """
        Comprehensive page deletion analysis.
        
        Analyzes object ID gaps and page count mismatches to identify
        suspected page deletions and their approximate positions.
        
        Returns:
            PageDeletionInfo with detailed deletion analysis
        """
        try:
            actual_count = len(self.reader.pages)
            
            # Get declared count from PDF structure
            declared_count = None
            try:
                trailer = self.reader.trailer
                root = trailer.get("/Root")
                if hasattr(root, "get_object"):
                    root = root.get_object()
                pages = root.get("/Pages")
                if hasattr(pages, "get_object"):
                    pages = pages.get_object()
                if isinstance(pages, dict):
                    declared_count = pages.get("/Count")
            except Exception:
                pass
            
            # Analyze object ID gaps
            page_objects = []
            for page in self.reader.pages:
                if hasattr(page, "indirect_reference"):
                    page_objects.append(page.indirect_reference.idnum)
            
            suspected_pages = []
            missing_ids = []
            gap_pattern = ""
            
            if page_objects:
                page_objects_sorted = sorted(page_objects)
                
                # Calculate gaps between consecutive page objects
                gaps = []
                gap_positions = []
                for i in range(len(page_objects_sorted) - 1):
                    gap_size = page_objects_sorted[i + 1] - page_objects_sorted[i] - 1
                    if gap_size > 0:
                        gaps.append(gap_size)
                        gap_positions.append(i + 1)  # Position after which gap occurs
                        # Track missing object IDs
                        missing_range = list(range(
                            page_objects_sorted[i] + 1,
                            page_objects_sorted[i + 1]
                        ))
                        missing_ids.extend(missing_range)
                
                # Analyze gap pattern
                if gaps:
                    avg_gap = sum(gaps) / len(gaps)
                    variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
                    std_dev = variance ** 0.5
                    
                    # Regular gaps (low variance) = normal PDF generation
                    # Irregular gaps (high variance) = potential deletion
                    if std_dev < avg_gap * 0.3:  # Low variance (<30% of mean)
                        gap_pattern = f"Regular gap pattern (avg: {avg_gap:.1f}, std: {std_dev:.1f}) - likely normal PDF structure"
                    else:
                        gap_pattern = f"Irregular gap pattern detected (avg: {avg_gap:.1f}, std: {std_dev:.1f}) - possible deletions"
                        
                        # Identify positions with unusually large gaps
                        for i, gap in enumerate(gaps):
                            if gap > avg_gap + std_dev:  # Significantly larger than average
                                suspected_pages.append(gap_positions[i])
                else:
                    gap_pattern = "No gaps in page object numbering"
            
            # Estimate original page count and detect deletions
            has_deletions = False
            estimated_original_count = declared_count  # Start with declared count
            estimated_deleted_count = 0
            
            if declared_count and declared_count > actual_count:
                # Declared count is higher - pages were deleted but count wasn't updated
                has_deletions = True
                estimated_deleted_count = declared_count - actual_count
                gap_pattern += f" | Declared count ({declared_count}) > actual ({actual_count}): {estimated_deleted_count} pages missing"
                estimated_original_count = declared_count
            elif page_objects and gaps:
                # Estimate original count from object ID range and gap pattern
                min_obj = min(page_objects)
                max_obj = max(page_objects)
                obj_range = max_obj - min_obj
                
                # If we have irregular gaps, estimate original page count
                if std_dev > avg_gap * 0.3:  # Irregular pattern
                    has_deletions = True
                    
                    # Note: Cannot accurately determine deletion count due to object renumbering
                    # Just report that deletions were detected
                    gap_pattern += f" | 1 or more page(s) deleted (exact count cannot be determined)"
                    estimated_original_count = None  # Unknown
            
            return PageDeletionInfo(
                has_deletions=has_deletions,
                current_page_count=actual_count,
                missing_object_count=len(missing_ids),
                gap_pattern=gap_pattern if gap_pattern else "No deletion indicators found"
            )
        
        except Exception as e:
            logger.error(f"Page deletion analysis failed: {str(e)}", exc_info=True)
            return PageDeletionInfo(
                current_page_count=len(self.reader.pages) if hasattr(self, 'reader') else 0,
                gap_pattern=f"Analysis failed: {str(e)}"
            )

    def analyze(self, filename: str) -> ForgeryStatus:
        try:
            total_points = 0
            flagged_functions = []
            observations = []
            detailed_explanations = {}

            explanation_map = {
                "identical_dates": "Creation and modification dates are identical (observational note).",
                "baseline_misalignment": "Text baseline misalignment detected (observational note).",
                "metadata": "The PDF metadata contains unusual or missing information, which can be a sign of forgery.",
                "high_object_density": "High object density was observed, which might indicate content layering or digital manipulation.",
                "moderate_object_density": "Moderate object density was observed (observational note).",
                "hidden_content": "Hidden or invisible content was detected, often used to disguise alterations.",
                "incremental_updates": "The PDF contains incremental updates, which may hide tampered edits.",
                "embedded_files_scripts": "Embedded files or JavaScript were found, often used for obfuscation or payload delivery.",
                "image_overlap_detected": "Suspicious overlapping images were found, possibly covering original content.",
                "inconsistent_fonts": "Fonts vary unusually across the document (observational note).",
                "missing_page_count": "Page count metadata is missing (observational note).",
                "page_count_mismatch": "Declared page count doesn't match actual count.",
                "page_structure_error": "Structural anomalies in the page layout were detected.",
                "page_object_disorder": "Unexpected object ordering found in the file.",
                "object_order_check_failed": "Failed to check object order (observational note).",
                "annotations_or_forms": "The document contains annotations or forms (observational note).",
                "layers_detected": "Multiple layers were detected (observational note).",
                "page_number_inconsistency": "Page numbers are not sequential, suggesting possible page deletion.",
                "missing_referenced_pages": "The PDF references pages that don't exist, indicating possible deletion.",
                "pages_missing": "The declared page count is higher than actual count (pages may have been deleted).",
                "text_overlap": "Text elements overlap abnormally, which may suggest copy-paste forgery.",
                "text_extraction_failed": "Failed to extract text (observational note).",
                "char_spacing": "Irregular character spacing detected, indicating possible text insertion.",
                "baseline_misalignment": "Text baseline misalignment found, common in forged documents.",
                "no_digital_signature": "Document lacks digital signature (observational note).",
                "digital_signature_present": "Document has digital signature (observational note).",
                "content_stream_anomalies": "Suspicious content stream patterns detected, suggesting manual text manipulation.",
                "page_label_gaps_detected": "Page label gaps found, indicating possible page deletion.",
            }

            observational_checks = {
                "identical_dates",
                "baseline_misalignment",
                "moderate_object_density",
                "inconsistent_fonts",
                "annotations_or_forms",
                "missing_page_count",
                "object_order_check_failed",
                "layers_detected",
                "page_number_inconsistency",
                "missing_referenced_pages",
                "text_extraction_failed",
                "digital_signature_present",
                "no_digital_signature",
            }

            # Run all checks
            checks = [
                self.check_metadata(),
                self.inspect_object_density(),
                self.detect_hidden_content(),
                self.check_incremental_updates(),
                self.check_embedded_files_scripts(),
                self.check_image_overlap(),
                self.check_fonts(),
                self.check_page_structure(),
                self.check_page_deletion(),
                self.check_object_order(),
                self.check_annotations_and_forms(),
                self.check_layers(),
                self.detect_text_modifications(),
                # New detection methods
                self.check_character_spacing(),
                self.check_text_baseline_alignment(),
                self.check_digital_signatures(),
                self.check_content_stream_anomalies(),
                self.check_page_labels(),
            ]

            # Process overlap detection separately
            overlap_info = self.detect_overlapping_text()
            if overlap_info.total_overlaps > 0:
                total_points += 2
                flagged_functions.append("text_overlap")
                detailed_explanations["text_overlap"] = explanation_map["text_overlap"]

            # Process page deletion analysis
            page_deletion_info = self.analyze_page_deletions()
            if page_deletion_info.has_deletions:
                total_points += 5  # Add points for page deletion
                deletion_msg = "Page deletion detected"
                flagged_functions.append(deletion_msg)
                detailed_explanations["page_deletion"] = f"Irregular gap pattern suggests page deletion. {page_deletion_info.gap_pattern}"

            # Process other checks
            for points, label in checks:
                if label:
                    if label in observational_checks:
                        observations.append(explanation_map.get(label, label))
                    else:
                        total_points += points
                        flagged_functions.append(label)

                        # Special handling for metadata
                        if label == "metadata":
                            metadata = self.reader.metadata
                            if metadata:
                                creation = metadata.get("/CreationDate", "N/A")
                                mod = metadata.get("/ModDate", "N/A")
                                producer = metadata.get("/Producer", "Unknown")
                            else:
                                creation = mod = "N/A"
                                producer = "Unknown"

                            detailed_explanations[label] = (
                                f"{explanation_map[label]}\n"
                                f" - Creation Date: {self.format_pdf_date(creation) if creation != 'N/A' else 'Not available'}\n"
                                f" - Modification Date: {self.format_pdf_date(mod) if mod != 'N/A' else 'Not available'}\n"
                                f" - Producer: {producer}"
                            )
                        else:
                            detailed_explanations[label] = explanation_map.get(
                                label, label
                            )

            # Determine status
            status = "No Suspicion"
            suspicion_level = "None"
            if total_points >= 7:
                status = "Suspicious"
                suspicion_level = "High"
            elif 4 <= total_points <= 6:
                status = "Might be Suspicious"
                suspicion_level = "Moderate"

            return ForgeryStatus(
                status=status,
                suspicion_level=suspicion_level,
                flagged_functions=flagged_functions,
                total_points=total_points,
                explanation="The PDF was analyzed for various forgery indicators. The following functions contributed to the suspicion level: "
                + ", ".join(flagged_functions)
                + ".",
                overlap_details=overlap_info
                if overlap_info.total_overlaps > 0
                else None,
                page_deletion_details=page_deletion_info
                if page_deletion_info.has_deletions
                else None,
                timestamp=datetime.now().isoformat(),
                filename=filename,
                explanations=detailed_explanations if detailed_explanations else None,
                observations=observations if observations else None,
            )
        except Exception as e:
            return ForgeryStatus(
                status="Error",
                suspicion_level="High",
                flagged_functions=["analysis_error"],
                total_points=10,
                explanation=f"Analysis failed with error: {str(e)}",
                overlap_details=None,
                timestamp=datetime.now().isoformat(),
                filename=filename,
            )
