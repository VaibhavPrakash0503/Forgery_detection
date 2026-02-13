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

            if creation != "N/A" and mod != "N/A" and creation[:16] != mod[:16]:
                return 2, "metadata"
            elif mod == "N/A":
                return 0, "No Modification Date"
            elif creation == "N/A":
                return 0, "No Creation Date"
            return 0, None
        except Exception:
            return 0, None

    def check_page_deletion(self) -> Tuple[int, Optional[str]]:
        try:
            # Check for page number inconsistencies
            page_labels = []
            for page in self.reader.pages:
                if "/Labels" in page:
                    page_labels.append(page["/Labels"])

            # Check if page numbers are sequential
            if len(page_labels) > 1:
                try:
                    numbers = [int(label) for label in page_labels if label.isdigit()]
                    if numbers != list(range(min(numbers), max(numbers) + 1)):
                        return 3, "page_number_inconsistency"
                except ValueError:
                    pass

            # Check for missing referenced pages
            root = self.reader.trailer["/Root"]
            if isinstance(root, dict) and "/PageLabels" in root:
                declared_pages = set(root["/PageLabels"].keys())
                actual_pages = set(str(i + 1) for i in range(len(self.reader.pages)))
                if declared_pages - actual_pages:
                    return 4, "missing_referenced_pages"

            return 0, None
        except Exception:
            return 0, None

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
            obj_per_page = total_objects / num_pages if num_pages else 0

            if obj_per_page > 50:
                return 1, "high_object_density"
            elif obj_per_page > 20:
                return 0, "moderate_object_density"
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
            with open(self.pdf_path, "rb") as f:
                data = f.read()
                eof_count = data.count(b"%%EOF")
                if eof_count > 1:
                    return 5, "incremental_updates"
            return 0, None
        except Exception:
            return 0, None

    def check_embedded_files_scripts(self) -> Tuple[int, Optional[str]]:
        try:
            root = self.reader.trailer["/Root"]
            names = root.get("/Names", {})
            has_embedded = isinstance(names, dict) and "/EmbeddedFiles" in names

            has_js = False
            if "/OpenAction" in root:
                try:
                    action = root["/OpenAction"]
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
                text_blocks = [
                    (fitz.Rect(b["bbox"]), b) for b in blocks if b.get("type") == 0
                ]
                overlaps_on_page = 0
                overlaps_data = []

                for (r1, b1), (r2, b2) in combinations(text_blocks, 2):
                    if r1.intersects(r2):
                        intersection = r1 & r2
                        if intersection.get_area() > 10:
                            overlaps_on_page += 1
                            text1 = self._extract_text_from_block(b1)
                            text2 = self._extract_text_from_block(b2)
                            if text1 and text2:
                                overlap_result = self._find_overlapping_text(
                                    text1, text2
                                )
                                if overlap_result:
                                    overlaps_data.append(overlap_result)

                if overlaps_on_page > 0:
                    pages_with_overlaps.append(page_num + 1)
                    page_overlap_content[str(page_num + 1)] = overlaps_data
                    total_overlaps += overlaps_on_page

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
            for page in self.doc:
                fonts = set(font[3] for font in page.get_fonts())
                font_sets.append(frozenset(fonts))

            if len(set(font_sets)) > 1:
                return 1, "inconsistent_fonts"
            return 0, None
        except Exception:
            return 0, None

    def check_object_order(self) -> Tuple[int, Optional[str]]:
        try:
            ids = []
            for page in self.reader.pages:
                if hasattr(page, "indirect_reference") and page.indirect_reference:
                    ids.append(page.indirect_reference.idnum)

            if ids and ids != sorted(ids):
                return 1, "page_object_disorder"
            return 0, None
        except Exception:
            return 1, "object_order_check_failed"

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
