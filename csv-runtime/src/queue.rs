//! Task queue for scheduling

// use crate::error::{RuntimeError, TransferCoordinatorError};

/// Task queue error
#[derive(Debug, thiserror::Error)]
pub enum TaskQueueError {
    /// Queue is full
    #[error("Queue is full")]
    Full,
    /// Queue is empty
    #[error("Queue is empty")]
    Empty,
}

/// Task queue for scheduling operations
pub struct TaskQueue<T> {
    /// Queue capacity
    capacity: usize,
    /// Queue items
    items: Vec<T>,
}

impl<T> TaskQueue<T> {
    /// Create a new task queue
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: Vec::with_capacity(capacity),
        }
    }

    /// Add a task to the queue
    pub fn push(&mut self, task: T) -> Result<(), TaskQueueError> {
        if self.items.len() >= self.capacity {
            return Err(TaskQueueError::Full);
        }
        self.items.push(task);
        Ok(())
    }

    /// Pop a task from the queue
    pub fn pop(&mut self) -> Result<T, TaskQueueError> {
        self.items.pop().ok_or(TaskQueueError::Empty)
    }

    /// Get the queue length
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the queue is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Check if the queue is full
    pub fn is_full(&self) -> bool {
        self.items.len() >= self.capacity
    }
}
