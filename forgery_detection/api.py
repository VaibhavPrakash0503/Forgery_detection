"""
FastAPI application and routes for PDF forgery detection.
"""

import tempfile
import os
import time
from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import JSONResponse
from PyPDF2 import PdfReader
import magic

from config import DEFAULT_CONFIG
from forgery_detection.models import ForgeryStatus
from forgery_detection.checker import PDFForgeryChecker
from forgery_detection.logging_config import (
    RequestIDMiddleware,
    StructuredLogger,
    calculate_file_hash
)

# Initialize structured logger
logger = StructuredLogger(__name__)

# Initialize FastAPI app with enhanced metadata
app = FastAPI(
    title="PDF Forgery Detection API",
    description="Analyze PDF documents for potential forgery indicators including text modifications, page deletions, and metadata anomalies.",
    version="2.0.0"
)

# Add request ID middleware
app.add_middleware(RequestIDMiddleware)


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    
    Returns basic API status, version information, and dependency checks.
    """
    health = {
        "status": "healthy",
        "version": "2.0.0",
        "service": "PDF Forgery Detection API",
        "checks": {}
    }
    
    # Check PyMuPDF
    try:
        import fitz
        health["checks"]["pymupdf"] = "ok"
    except Exception as e:
        health["checks"]["pymupdf"] = f"error: {str(e)}"
        health["status"] = "degraded"
    
    # Check PyPDF2
    try:
        from PyPDF2 import PdfReader
        health["checks"]["pypdf2"] = "ok"
    except Exception as e:
        health["checks"]["pypdf2"] = f"error: {str(e)}"
        health["status"] = "degraded"
    
    # Check temp directory writable
    try:
        with tempfile.NamedTemporaryFile() as tmp:
            pass
        health["checks"]["temp_dir"] = "ok"
    except Exception as e:
        health["checks"]["temp_dir"] = f"error: {str(e)}"
        health["status"] = "unhealthy"
    
    return health


async def stream_file_to_temp(upload_file: UploadFile, max_size: int) -> tuple[str, int, bytes]:
    """
    Stream uploaded file to temporary file without loading entirely into memory.
    
    Args:
        upload_file: FastAPI UploadFile object
        max_size: Maximum allowed file size in bytes
        
    Returns:
        Tuple of (temp_path, file_size, file_contents_for_hash)
        
    Raises:
        HTTPException: If file exceeds max size
    """
    temp_path = tempfile.mktemp(suffix=".pdf")
    size = 0
    chunks = []
    
    try:
        with open(temp_path, 'wb') as f:
            while chunk := await upload_file.read(8192):  # 8KB chunks
                size += len(chunk)
                if size > max_size:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size: {max_size / (1024*1024):.0f}MB"
                    )
                f.write(chunk)
                chunks.append(chunk)
        
        # Combine chunks for hash calculation
        contents = b''.join(chunks)
        return temp_path, size, contents
        
    except HTTPException:
        raise
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise


@app.post(
    "/forgery-check",
    response_model=ForgeryStatus,
    summary="Analyze PDF for forgery indicators",
    description="""
    Upload a PDF file to analyze for potential forgery indicators including:
    
    - **Text modifications**: Detects added/altered text via font analysis and character spacing
    - **Page deletion**: Identifies missing pages through structural analysis and page labels
    - **Metadata anomalies**: Checks for suspicious or missing metadata
    - **Content overlaps**: Finds overlapping text/images (copy-paste indicators)
    - **Digital signatures**: Verifies presence of signatures
    - **Baseline alignment**: Detects misaligned text common in forgeries
    - **Content stream analysis**: Identifies manual text positioning
    
    Returns a detailed report with suspicion level (None/Moderate/High) and
    specific findings for each check performed.
    
    **File Requirements:**
    - Maximum file size: 50MB
    - File type: PDF only
    """,
    responses={
        200: {
            "description": "Analysis completed successfully",
        },
        400: {"description": "Invalid PDF file or file type"},
        413: {"description": "File too large (max 50MB)"},
        500: {"description": "Analysis error"}
    }
)
async def check_pdf(request: Request, file: UploadFile = File(...)):
    """
    Analyze uploaded PDF for forgery indicators.
    
    Args:
        request: FastAPI request object (for logging)
        file: Uploaded PDF file
        
    Returns:
        ForgeryStatus: Detailed analysis results
        
    Raises:
        HTTPException: For validation errors or processing failures
    """
    temp_path = None
    start_time = time.time()
    
    try:
        # Stream file to temp location
        temp_path, file_size, contents = await stream_file_to_temp(
            file, 
            DEFAULT_CONFIG.max_file_size
        )
        
        # Calculate file hash for tracking
        file_hash = calculate_file_hash(contents)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Log incoming request
        logger.log_request(
            pdf_filename=file.filename or "unknown.pdf",
            file_size=file_size,
            file_hash=file_hash,
            client_ip=client_ip
        )
        
        # Validate file type using magic number
        try:
            file_type = magic.from_buffer(contents[:2048], mime=True)
            if file_type != 'application/pdf':
                logger.warning(
                    "Invalid file type rejected",
                    pdf_filename=file.filename,
                    file_type=file_type,
                    client_ip=client_ip
                )
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid file type: {file_type}. Expected: application/pdf"
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "MIME type detection failed",
                error=str(e),
                pdf_filename=file.filename
            )
            # Continue anyway - fallback validation will happen when opening PDF
        
        # Validate PDF structure
        try:
            test_reader = PdfReader(temp_path)
        except Exception as e:
            logger.log_error(
                pdf_filename=file.filename or "unknown.pdf",
                error=str(e),
                error_type="invalid_pdf_structure"
            )
            raise HTTPException(
                status_code=400,
                detail=f"Corrupted or invalid PDF: {str(e)}"
            )
        
        # Perform forgery analysis using context manager
        with PDFForgeryChecker(temp_path) as checker:
            result = checker.analyze(file.filename or "unknown.pdf")
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log successful response
        logger.log_response(
            pdf_filename=file.filename or "unknown.pdf",
            status=result.status,
            total_points=result.total_points,
            duration=duration
        )
        
        return JSONResponse(content=result.model_dump())

    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        duration = time.time() - start_time
        logger.log_error(
            pdf_filename=file.filename or "unknown.pdf",
            error=str(e),
            error_type="unexpected_error"
        )
        logger.error(
            "Unexpected error during analysis",
            error=str(e),
            duration_seconds=round(duration, 3)
        )
        raise HTTPException(
            status_code=500,
            detail="Internal server error during PDF analysis"
        )
    finally:
        # Clean up temporary file
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
                logger.debug("Cleaned up temp file", temp_file=temp_path)
        except Exception as e:
            logger.warning("Failed to clean up temp file", error=str(e), temp_file=temp_path)
