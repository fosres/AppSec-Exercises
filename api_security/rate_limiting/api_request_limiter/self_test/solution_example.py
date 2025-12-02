"""
EXAMPLE: What Your Solution Should Look Like When Complete
===========================================================

This file shows the correct implementation for reference.
Copy rate_limiter_exercise.py and implement your own solution!
"""

from typing import List, Tuple


def check_rate_limit(request_times: List[float], 
                     current_time: float, 
                     max_requests: int) -> Tuple[bool, float]:
    """
    Check if an API request should be allowed based on rate limiting.
    
    CORRECT IMPLEMENTATION - for reference only!
    
    Args:
        max_requests: REQUIRED parameter - no default value!
    """
    # Step 1: Filter to only requests in the last 60 seconds
    window_start = current_time - 60.0
    recent_requests = [t for t in request_times if t >= window_start]
    
    # Step 2: Check if under limit
    if len(recent_requests) < max_requests:
        return (True, 0.0)
    
    # Step 3: Rate limit exceeded - calculate retry time
    oldest_request = recent_requests[0]
    retry_after = (oldest_request + 60.0) - current_time
    retry_after = max(0.0, retry_after)  # Ensure non-negative
    
    return (False, retry_after)


# Test it!
if __name__ == "__main__":
    print("Testing correct implementation...")
    print()
    
    # Test 1
    result1 = check_rate_limit([100.0, 110.0, 120.0], 121.0, 5)
    print(f"Test 1: {result1}")
    assert result1 == (True, 0.0), "Failed!"
    print("✅ PASS\n")
    
    # Test 2
    result2 = check_rate_limit([100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5)
    print(f"Test 2: {result2}")
    assert result2 == (False, 38.0), "Failed!"
    print("✅ PASS\n")
    
    print("All tests passed! This is what you're aiming for.")
    print()
    print("Now go implement it yourself in rate_limiter_exercise.py!")
