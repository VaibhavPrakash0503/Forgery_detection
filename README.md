# PDF Forgery Detection API

A production-ready FastAPI application for detecting forgery indicators in PDF documents using advanced structural analysis, metadata inspection, and content examination.

## Features

- **17+ Detection Methods**: Text modifications, page deletions, metadata anomalies, content overlaps, and more
- **Structured Logging**: JSON-formatted logs with request ID tracking for correlation
- **Streaming File Upload**: Memory-efficient handling of large files (up to 50MB)
- **Concurrent Request Support**: Handles multiple simultaneous requests safely
- **Comprehensive Testing**: Unit tests, concurrent load tests, and performance benchmarks

## Project Structure

```
forgery_detection/
├── __init__.py           # Package initialization
├── models.py             # Pydantic data models
├── checker.py            # Core PDF forgery detection logic
├── logging_config.py     # Structured logging configuration
├── api.py                # FastAPI routes and endpoints
└── main.py               # Application entry point

tests/
├── conftest.py           # Pytest fixtures
├── test_concurrent.py    # Concurrent request tests
├── test_logging.py       # Logging functionality tests
└── load_test.py          # Standalone load testing script

config.py                 # Configuration management
requirements.txt          # Python dependencies
```

## Installation

### 1. Clone the repository

```bash
cd /home/vaibhav/coding/projects/Forgery_Detection_FastAPI
```

### 2. Create and activate virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Linux/Mac
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the API

### Development Server

```bash
python -m forgery_detection.main
```

The API will be available at `http://localhost:8000`

### Production Server

```bash
uvicorn forgery_detection.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Usage

### Health Check

```bash
curl http://localhost:8000/health
```

### Analyze PDF

```bash
curl -X POST http://localhost:8000/forgery-check \
  -F "file=@/path/to/document.pdf"
```

### Response Example

```json
{
  "status": "No Suspicion",
  "suspicion_level": "None",
  "flagged_functions": [],
  "total_points": 0,
  "timestamp": "2026-02-17T20:54:26.123456",
  "filename": "document.pdf",
  "observations": [
    "Document has digital signature (observational note)."
  ]
}
```

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Concurrent Request Tests

```bash
pytest tests/test_concurrent.py -v -s
```

### Run Logging Tests

```bash
pytest tests/test_logging.py -v
```

### Run Load Test (Standalone)

```bash
# Start the API first
python -m forgery_detection.main

# In another terminal:
python tests/load_test.py --concurrent 50 --requests 1000
```

Load test options:
- `--url`: API base URL (default: http://localhost:8000)
- `--concurrent`: Number of concurrent requests (default: 10)
- `--requests`: Total number of requests (default: 100)
- `--pdf`: Path to PDF file (optional, creates one if not provided)

## Logging

The API uses structured JSON logging with request ID tracking:

```json
{
  "timestamp": "2026-02-17T20:54:26.123456",
  "level": "INFO",
  "logger": "forgery_detection.api",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "message": "PDF analysis request received",
  "event": "request_received",
  "filename": "document.pdf",
  "file_size_bytes": 102400,
  "file_hash": "abc123...",
  "client_ip": "127.0.0.1"
}
```

Each request gets a unique `X-Request-ID` header for correlation across logs.

## Configuration

Edit `config.py` to adjust detection thresholds and API settings:

```python
class ForgeryDetectionConfig:
    # File size limits
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    
    # Detection thresholds
    suspicion_high_threshold: int = 7
    suspicion_moderate_min: int = 4
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"  # or "text"
    log_file: Optional[str] = None
```

## Detection Methods

1. **Metadata Analysis**: Missing or suspicious creation/modification dates
2. **Page Deletion Detection**: Gaps in page object numbering
3. **Object Density Analysis**: Unusually high object counts
4. **Text Modifications**: Font frequency and consistency analysis
5. **Character Spacing**: Irregular spacing patterns
6. **Baseline Alignment**: Text alignment consistency
7. **Overlapping Content**: Text/image overlaps
8. **Incremental Updates**: Suspicious PDF update patterns
9. **Embedded Files/Scripts**: JavaScript or embedded files
10. **Digital Signatures**: Presence/absence of signatures
11. **Content Stream Anomalies**: Manual text positioning
12. **Page Labels**: Gaps in page numbering
13. **And more...**

## Performance

Tested performance metrics:
- **Single request**: ~0.5-2s depending on PDF complexity
- **10 concurrent requests**: ~2-4s total
- **50 concurrent requests**: ~8-12s total
- **Memory usage**: Stable under load, <250MB increase for 100 requests

## Development

### Code Quality

```bash
# Format code
black forgery_detection/ tests/

# Type checking
mypy forgery_detection/

# Linting
ruff check forgery_detection/ tests/
```

### Adding New Detection Methods

1. Add method to `PDFForgeryChecker` class in `checker.py`
2. Return `Tuple[int, Optional[str]]` (points, label)
3. Add to `checks` list in `analyze()` method
4. Add explanation to `explanation_map`
5. Write tests

## License

[Your License Here]

## Contributing

[Contributing Guidelines]
