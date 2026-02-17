#!/usr/bin/env python3
"""
Standalone load testing script for PDF Forgery Detection API.

Usage:
    python tests/load_test.py --concurrent 50 --requests 1000 --url http://localhost:8000
"""

import argparse
import asyncio
import time
import statistics
from pathlib import Path
import sys
import psutil
import os

import httpx
from PyPDF2 import PdfWriter


def create_sample_pdf(path: Path):
    """Create a simple PDF for testing."""
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    
    with open(path, 'wb') as f:
        writer.write(f)


async def make_request(client: httpx.AsyncClient, pdf_data: bytes, request_num: int):
    """Make a single API request."""
    files = {"file": (f"test_{request_num}.pdf", pdf_data, "application/pdf")}
    
    start_time = time.time()
    try:
        response = await client.post("/forgery-check", files=files)
        duration = time.time() - start_time
        
        return {
            "success": response.status_code == 200,
            "status_code": response.status_code,
            "duration": duration,
            "error": None
        }
    except Exception as e:
        duration = time.time() - start_time
        return {
            "success": False,
            "status_code": None,
            "duration": duration,
            "error": str(e)
        }


async def run_load_test(base_url: str, concurrent: int, total_requests: int, pdf_data: bytes):
    """
    Run load test with specified parameters.
    
    Args:
        base_url: API base URL
        concurrent: Number of concurrent requests
        total_requests: Total number of requests to make
        pdf_data: PDF file data to upload
    """
    results = []
    process = psutil.Process(os.getpid())
    
    # Get baseline memory
    baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"\n{'='*70}")
    print(f"LOAD TEST: {total_requests} requests with {concurrent} concurrent")
    print(f"{'='*70}\n")
    
    async with httpx.AsyncClient(base_url=base_url, timeout=30.0) as client:
        # Calculate batches
        num_batches = (total_requests + concurrent - 1) // concurrent
        
        overall_start = time.time()
        
        for batch_num in range(num_batches):
            batch_start = time.time()
            
            # Determine batch size (last batch might be smaller)
            batch_size = min(concurrent, total_requests - batch_num * concurrent)
            
            # Create tasks for this batch
            tasks = []
            for i in range(batch_size):
                request_num = batch_num * concurrent + i
                task = make_request(client, pdf_data, request_num)
                tasks.append(task)
            
            # Execute batch
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)
            
            batch_duration = time.time() - batch_start
            
            # Progress update
            completed = len(results)
            success_count = sum(1 for r in results if r["success"])
            
            # Memory check
            current_memory = process.memory_info().rss / 1024 / 1024
            memory_increase = current_memory - baseline_memory
            
            print(f"Batch {batch_num + 1}/{num_batches}: "
                  f"{batch_size} requests in {batch_duration:.2f}s | "
                  f"Total: {completed}/{total_requests} | "
                  f"Success: {success_count} | "
                  f"Memory: +{memory_increase:.1f}MB")
        
        overall_duration = time.time() - overall_start
    
    # Calculate statistics
    successful_results = [r for r in results if r["success"]]
    failed_results = [r for r in results if not r["success"]]
    
    durations = [r["duration"] for r in successful_results]
    
    print(f"\n{'='*70}")
    print("RESULTS")
    print(f"{'='*70}")
    print(f"\nTotal Requests:     {total_requests}")
    print(f"Successful:         {len(successful_results)} ({len(successful_results)/total_requests*100:.1f}%)")
    print(f"Failed:             {len(failed_results)} ({len(failed_results)/total_requests*100:.1f}%)")
    print(f"\nTotal Duration:     {overall_duration:.2f}s")
    print(f"Requests/sec:       {total_requests/overall_duration:.2f}")
    
    if durations:
        print(f"\nResponse Times:")
        print(f"  Min:              {min(durations):.3f}s")
        print(f"  Max:              {max(durations):.3f}s")
        print(f"  Mean:             {statistics.mean(durations):.3f}s")
        print(f"  Median:           {statistics.median(durations):.3f}s")
        print(f"  Std Dev:          {statistics.stdev(durations) if len(durations) > 1 else 0:.3f}s")
        
        # Percentiles
        sorted_durations = sorted(durations)
        p50 = sorted_durations[int(len(sorted_durations) * 0.50)]
        p90 = sorted_durations[int(len(sorted_durations) * 0.90)]
        p95 = sorted_durations[int(len(sorted_durations) * 0.95)]
        p99 = sorted_durations[int(len(sorted_durations) * 0.99)]
        
        print(f"\nPercentiles:")
        print(f"  50th (p50):       {p50:.3f}s")
        print(f"  90th (p90):       {p90:.3f}s")
        print(f"  95th (p95):       {p95:.3f}s")
        print(f"  99th (p99):       {p99:.3f}s")
    
    # Memory stats
    final_memory = process.memory_info().rss / 1024 / 1024
    total_memory_increase = final_memory - baseline_memory
    
    print(f"\nMemory Usage:")
    print(f"  Baseline:         {baseline_memory:.1f}MB")
    print(f"  Final:            {final_memory:.1f}MB")
    print(f"  Increase:         +{total_memory_increase:.1f}MB")
    
    # Error summary
    if failed_results:
        print(f"\nErrors:")
        error_types = {}
        for r in failed_results:
            error_key = r["error"] or f"HTTP {r['status_code']}"
            error_types[error_key] = error_types.get(error_key, 0) + 1
        
        for error, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {error}: {count}")
    
    print(f"{'='*70}\n")
    
    return {
        "total": total_requests,
        "successful": len(successful_results),
        "failed": len(failed_results),
        "duration": overall_duration,
        "requests_per_sec": total_requests / overall_duration,
        "memory_increase_mb": total_memory_increase
    }


def main():
    parser = argparse.ArgumentParser(description="Load test PDF Forgery Detection API")
    parser.add_argument("--url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--concurrent", type=int, default=10, help="Concurrent requests")
    parser.add_argument("--requests", type=int, default=100, help="Total requests")
    parser.add_argument("--pdf", help="Path to PDF file (optional, will create one if not provided)")
    
    args = parser.parse_args()
    
    # Prepare PDF
    if args.pdf:
        pdf_path = Path(args.pdf)
        if not pdf_path.exists():
            print(f"Error: PDF file not found: {pdf_path}")
            sys.exit(1)
    else:
        # Create temporary PDF
        pdf_path = Path("/tmp/load_test_sample.pdf")
        print(f"Creating sample PDF: {pdf_path}")
        create_sample_pdf(pdf_path)
    
    # Load PDF data
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()
    
    print(f"PDF size: {len(pdf_data)} bytes")
    
    # Run load test
    try:
        results = asyncio.run(run_load_test(
            args.url,
            args.concurrent,
            args.requests,
            pdf_data
        ))
        
        # Exit with error code if too many failures
        if results["failed"] / results["total"] > 0.1:  # More than 10% failures
            print("⚠️  WARNING: High failure rate detected!")
            sys.exit(1)
        
        print("✓ Load test completed successfully")
        
    except KeyboardInterrupt:
        print("\n\nLoad test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError running load test: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
