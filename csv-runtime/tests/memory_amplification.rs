//! Memory amplification tests
//!
//! These tests simulate high-volume RPC response scenarios to ensure
//! the runtime can handle memory pressure without exhaustion.

use csv_runtime::backpressure::{BackpressureMode, BackpressureSink};
use csv_runtime::queue::TaskQueue;

#[test]
fn test_task_queue_backpressure_reject() {
    let mut queue = TaskQueue::new(10);

    // Fill queue to capacity
    for i in 0..10 {
        assert!(queue.push(i).is_ok());
    }

    // Attempt to add more should fail
    assert!(queue.push(11).is_err());

    // Queue should be at capacity
    assert_eq!(queue.len(), 10);
    assert!(queue.is_full());
}

#[test]
fn test_task_queue_backpressure_drop_oldest() {
    // This test simulates DropOldest behavior
    let mut queue = TaskQueue::new(10);

    // Fill queue to capacity
    for i in 0..10 {
        assert!(queue.push(i).is_ok());
    }

    // Simulate dropping oldest by popping and pushing
    let _ = queue.pop();
    assert!(queue.push(10).is_ok());

    // Queue should still be at capacity
    assert_eq!(queue.len(), 10);
}

#[test]
fn test_memory_amplification_10k_responses() {
    // Simulate 10K RPC responses being queued
    let mut queue = TaskQueue::new(10000);

    // Fill queue with 10K items
    for i in 0..10000 {
        assert!(queue.push(i).is_ok());
    }

    // Verify queue depth
    assert_eq!(queue.len(), 10000);
    assert!(queue.is_full());

    // Verify we can drain the queue
    let mut count = 0;
    while !queue.is_empty() {
        let _ = queue.pop();
        count += 1;
    }
    assert_eq!(count, 10000);
}

#[test]
fn test_backpressure_pressure_level() {
    struct MockSink {
        depth: usize,
        max_depth: usize,
    }

    impl BackpressureSink for MockSink {
        fn queue_depth(&self) -> usize {
            self.depth
        }

        fn max_queue_depth(&self) -> usize {
            self.max_depth
        }
    }

    let sink = MockSink {
        depth: 750,
        max_depth: 1000,
    };

    // Pressure level should be 75%
    assert_eq!(sink.pressure_level(), 75);

    // Should be under pressure (>75%)
    assert!(sink.is_under_pressure());

    let sink_low = MockSink {
        depth: 500,
        max_depth: 1000,
    };

    // Pressure level should be 50%
    assert_eq!(sink_low.pressure_level(), 50);

    // Should NOT be under pressure (<75%)
    assert!(!sink_low.is_under_pressure());
}

#[test]
fn test_backpressure_mode_display() {
    assert_eq!(format!("{}", BackpressureMode::Reject), "Reject");
    assert_eq!(format!("{}", BackpressureMode::DropOldest), "DropOldest");
    assert_eq!(format!("{}", BackpressureMode::Block), "Block");
}
