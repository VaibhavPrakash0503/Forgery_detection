import tempfile
import os
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Tuple, Any
from datetime import datetime
import fitz  # PyMuPDF
from PyPDF2 import PdfReader
from itertools import combinations
from pdfminer.high_level import extract_text

app = FastAPI()


class OverlapInfo(BaseModel):
    pages_with_overlaps: List[int] = Field(default_factory=list)
    total_overlaps: int = 0
    warning: Optional[str] = None
    content: Dict[str, Any] = Field(default_factory=dict)


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


class PDFForgeryChecker:
    def __init__(self, pdf_path):
        self.pdf_path = pdf_path
        self.reader = PdfReader(pdf_path)
        self.doc = fitz.open(pdf_path)

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

            # Both dates exist - check if they're identical (suspicious)
            if creation != "N/A" and mod != "N/A":
                # Compare first 14 chars (YYYYMMDDHHmmss) - exact same timestamp
                if creation[:14] == mod[:14]:
                    return 2, "Creation and modification dates are identical"

            # Both dates exist and different (normal)
            return 3, None

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

                if overlaps_data:  # Changed from overlaps_on_page
                    pages_with_overlaps.append(page_num + 1)
                    page_overlap_content[str(page_num + 1)] = overlaps_data
                    total_overlaps += len(overlaps_data)  # Count actual overlaps found

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
        """Detect signs of text being added or modified after document creation"""
        try:
            suspicious_pages = []
            indicators = []

            for page_num in range(len(self.doc)):
                page = self.doc[page_num]
                blocks = page.get_text("dict").get("blocks", [])

                font_data = []

                for block in blocks:
                    if block.get("type") == 0:  # Text block
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                font_data.append(
                                    {
                                        "font": span.get("font", ""),
                                        "size": span.get("size", 0),
                                        "color": span.get("color", 0),
                                    }
                                )

                if len(font_data) < 2:
                    continue

                # Extract fonts and sizes
                fonts = [f["font"] for f in font_data]
                sizes = [f["size"] for f in font_data if f["size"] > 0]
                colors = [f["color"] for f in font_data]

                page_suspicious = False

                # Check 1: Font diversity (lowered threshold)
                unique_fonts = set(fonts)
                if len(unique_fonts) > 3:  # Changed from 4
                    page_suspicious = True
                    indicators.append(
                        f"Page {page_num + 1}: {len(unique_fonts)} different fonts"
                    )

                # Check 2: Single-use fonts (very suspicious for edits)
                font_counts = {}
                for font in fonts:
                    font_counts[font] = font_counts.get(font, 0) + 1

                single_use_fonts = [f for f, count in font_counts.items() if count == 1]
                if len(single_use_fonts) >= 1:  # Even 1 single-use font is suspicious
                    page_suspicious = True
                    indicators.append(
                        f"Page {page_num + 1}: Font used only once (likely added text)"
                    )

                # Check 3: Font size variance
                if len(sizes) > 3:
                    avg_size = sum(sizes) / len(sizes)
                    # Check for ANY size that differs significantly
                    for size in sizes:
                        if abs(size - avg_size) > avg_size * 0.30:  # Lowered from 0.4
                            page_suspicious = True
                            indicators.append(
                                f"Page {page_num + 1}: Inconsistent font size detected"
                            )
                            break

                # Check 4: Color inconsistencies (added text often has different color value)
                unique_colors = set(colors)
                if len(unique_colors) > 2:  # More than 2 colors
                    page_suspicious = True
                    indicators.append(f"Page {page_num + 1}: Multiple text colors")

                if page_suspicious:
                    suspicious_pages.append(page_num + 1)

            if suspicious_pages:
                suspicion = min(
                    len(suspicious_pages) * 2, 6
                )  # 2 points per page, max 6
                message = f"Text modifications detected on page(s) {suspicious_pages}: {'; '.join(set(indicators))}"
                return suspicion, message

            return 0, None

        except Exception as e:
            return 0, None

    def analyze(self, filename: str) -> ForgeryStatus:
        try:
            total_points = 0
            flagged_functions = []
            observations = []
            detailed_explanations = {}

            explanation_map = {
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
            }

            observational_checks = {
                "moderate_object_density",
                "inconsistent_fonts",
                "annotations_or_forms",
                "missing_page_count",
                "object_order_check_failed",
                "layers_detected",
                "page_number_inconsistency",
                "missing_referenced_pages",
                "text_extraction_failed",
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
            ]

            # Process overlap detection separately
            overlap_info = self.detect_overlapping_text()
            if overlap_info.total_overlaps > 0:
                total_points += 2
                flagged_functions.append("text_overlap")
                detailed_explanations["text_overlap"] = explanation_map["text_overlap"]

            # Process other checks
            # Inside the analyze method, where you process the checks:
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


@app.post("/forgery-check", response_model=ForgeryStatus)
async def check_pdf(file: UploadFile = File(...)):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            temp_path = tmp.name
            contents = await file.read()
            tmp.write(contents)

        checker = PDFForgeryChecker(temp_path)
        result = checker.analyze(file.filename or "unknown.pdf")
        checker.close()

        return JSONResponse(content=result.model_dump())

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("forgery_api:app", host="127.0.0.1", port=8000, reload=True)

    # http://localhost:8000/docs
