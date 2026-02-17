"""
Pytest configuration and fixtures for testing.
"""

import pytest
import tempfile
import os
from pathlib import Path
from httpx import AsyncClient
from PyPDF2 import PdfWriter

from forgery_detection.api import app


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
async def client():
    """Create async test client for API."""
    from httpx import AsyncClient
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_pdf(temp_dir):
    """
    Create a simple valid PDF for testing.
    
    Returns path to the PDF file.
    """
    pdf_path = temp_dir / "sample.pdf"
    
    # Create a simple PDF using PyPDF2
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    
    with open(pdf_path, 'wb') as f:
        writer.write(f)
    
    return pdf_path


@pytest.fixture
def large_pdf(temp_dir):
    """
    Create a large PDF (10MB) for testing file size limits.
    
    Returns path to the PDF file.
    """
    pdf_path = temp_dir / "large.pdf"
    
    writer = PdfWriter()
    # Add many pages to make it large
    for _ in range(100):
        writer.add_blank_page(width=800, height=1000)
    
    with open(pdf_path, 'wb') as f:
        writer.write(f)
    
    return pdf_path


@pytest.fixture
def invalid_file(temp_dir):
    """Create a non-PDF file for testing validation."""
    file_path = temp_dir / "invalid.txt"
    
    with open(file_path, 'w') as f:
        f.write("This is not a PDF file")
    
    return file_path
