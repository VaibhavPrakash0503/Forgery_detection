"""
Concurrent request testing for PDF Forgery Detection API.

Tests the API's ability to handle multiple simultaneous requests,
memory management, and resource cleanup under load.
"""

import pytest
import asyncio
import psutil
import os
from pathlib import Path
from httpx import AsyncClient
import time

from forgery_detection.api import app


@pytest.mark.asyncio
class TestConcurrentRequests:
    """Test suite for concurrent request handling."""
    
    async def test_10_concurrent_requests(self, sample_pdf):
        """Test 10 concurrent requests with small PDFs."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            # Prepare file data
            with open(sample_pdf, 'rb') as f:
                pdf_data = f.read()
            
            # Create tasks for concurrent requests
            tasks = []
            for i in range(10):
                files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            # Execute concurrently
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            # Verify all succeeded
            successful = 0
            for response in responses:
                if not isinstance(response, Exception):
                    assert response.status_code == 200
                    successful += 1
            
            assert successful == 10, f"Only {successful}/10 requests succeeded"
            print(f"\n✓ 10 concurrent requests completed in {duration:.2f}s")
    
    async def test_50_concurrent_requests(self, sample_pdf):
        """Test 50 concurrent requests - stress test."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            with open(sample_pdf, 'rb') as f:
                pdf_data = f.read()
            
            tasks = []
            for i in range(50):
                files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 200)
            
            # Allow some failures under heavy load, but most should succeed
            assert successful >= 45, f"Only {successful}/50 requests succeeded"
            print(f"\n✓ {successful}/50 concurrent requests completed in {duration:.2f}s")
    
    async def test_memory_usage_under_load(self, sample_pdf):
        """Test that memory doesn't grow excessively under concurrent load."""
        process = psutil.Process(os.getpid())
        
        # Get baseline memory
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        async with AsyncClient(app=app, base_url="http://test") as client:
            with open(sample_pdf, 'rb') as f:
                pdf_data = f.read()
            
            # Run 100 requests in batches of 10
            for batch in range(10):
                tasks = []
                for i in range(10):
                    files = {"file": (f"test_{batch}_{i}.pdf", pdf_data, "application/pdf")}
                    task = client.post("/forgery-check", files=files)
                    tasks.append(task)
                
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Check memory after each batch
                current_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_increase = current_memory - baseline_memory
                
                # Memory shouldn't grow more than 200MB
                assert memory_increase < 200, f"Memory increased by {memory_increase:.2f}MB"
        
        # Final memory check
        final_memory = process.memory_info().rss / 1024 / 1024
        total_increase = final_memory - baseline_memory
        
        print(f"\n✓ Memory increase after 100 requests: {total_increase:.2f}MB")
        assert total_increase < 250, f"Excessive memory growth: {total_increase:.2f}MB"
    
    async def test_temp_file_cleanup(self, sample_pdf, temp_dir):
        """Verify temporary files are cleaned up after requests."""
        # Get initial temp file count
        temp_files_before = len(list(Path(tempfile.gettempdir()).glob("*.pdf")))
        
        async with AsyncClient(app=app, base_url="http://test") as client:
            with open(sample_pdf, 'rb') as f:
                pdf_data = f.read()
            
            # Make 20 concurrent requests
            tasks = []
            for i in range(20):
                files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Wait a moment for cleanup
        await asyncio.sleep(0.5)
        
        # Check temp files after
        temp_files_after = len(list(Path(tempfile.gettempdir()).glob("*.pdf")))
        
        # Should have same or fewer temp files (cleanup successful)
        leaked_files = temp_files_after - temp_files_before
        assert leaked_files <= 0, f"Leaked {leaked_files} temporary files"
        print(f"\n✓ No temporary file leaks detected")
    
    async def test_error_handling_under_concurrent_load(self, sample_pdf, invalid_file):
        """Test that errors in some requests don't affect others."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            with open(sample_pdf, 'rb') as f:
                valid_pdf_data = f.read()
            
            with open(invalid_file, 'rb') as f:
                invalid_data = f.read()
            
            tasks = []
            # Mix valid and invalid requests
            for i in range(20):
                if i % 3 == 0:
                    # Invalid file
                    files = {"file": (f"invalid_{i}.txt", invalid_data, "text/plain")}
                else:
                    # Valid PDF
                    files = {"file": (f"valid_{i}.pdf", valid_pdf_data, "application/pdf")}
                
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Count successes and expected failures
            successes = 0
            expected_failures = 0
            
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
                    continue
                
                if i % 3 == 0:
                    # Should fail (invalid file)
                    assert response.status_code == 400
                    expected_failures += 1
                else:
                    # Should succeed (valid PDF)
                    assert response.status_code == 200
                    successes += 1
            
            print(f"\n✓ {successes} valid requests succeeded, {expected_failures} invalid requests properly rejected")
            assert successes >= 12  # At least 12/14 valid requests should succeed
    
    async def test_request_id_uniqueness(self, sample_pdf):
        """Verify each concurrent request gets a unique request ID."""
        async with AsyncClient(app=app, base_url="http://test") as client:
            with open(sample_pdf, 'rb') as f:
                pdf_data = f.read()
            
            tasks = []
            for i in range(20):
                files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Extract request IDs from response headers
            request_ids = set()
            for response in responses:
                if not isinstance(response, Exception) and response.status_code == 200:
                    request_id = response.headers.get("X-Request-ID")
                    assert request_id is not None, "Missing X-Request-ID header"
                    request_ids.add(request_id)
            
            # All request IDs should be unique
            assert len(request_ids) == 20, f"Only {len(request_ids)}/20 unique request IDs"
            print(f"\n✓ All 20 concurrent requests have unique request IDs")


@pytest.mark.asyncio
async def test_performance_benchmark(sample_pdf):
    """Benchmark API performance under various load levels."""
    results = {}
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        with open(sample_pdf, 'rb') as f:
            pdf_data = f.read()
        
        # Test different concurrency levels
        for concurrency in [1, 5, 10, 20]:
            tasks = []
            for i in range(concurrency):
                files = {"file": (f"test_{i}.pdf", pdf_data, "application/pdf")}
                task = client.post("/forgery-check", files=files)
                tasks.append(task)
            
            start_time = time.time()
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            duration = time.time() - start_time
            
            successful = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 200)
            avg_time = duration / concurrency if concurrency > 0 else 0
            
            results[concurrency] = {
                "total_time": duration,
                "avg_time_per_request": avg_time,
                "successful": successful
            }
    
    # Print benchmark results
    print("\n" + "="*60)
    print("PERFORMANCE BENCHMARK RESULTS")
    print("="*60)
    for concurrency, data in results.items():
        print(f"\nConcurrency: {concurrency}")
        print(f"  Total time: {data['total_time']:.2f}s")
        print(f"  Avg per request: {data['avg_time_per_request']:.3f}s")
        print(f"  Successful: {data['successful']}/{concurrency}")
    print("="*60)
