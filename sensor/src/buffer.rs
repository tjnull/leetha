use std::collections::VecDeque;

/// In-memory circular buffer with configurable max size in bytes.
/// When full, oldest frames are dropped.
pub struct RingBuffer {
    frames: VecDeque<Vec<u8>>,
    current_bytes: usize,
    max_bytes: usize,
}

impl RingBuffer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            frames: VecDeque::new(),
            current_bytes: 0,
            max_bytes,
        }
    }

    pub fn push(&mut self, frame: Vec<u8>) {
        let frame_size = frame.len();
        if frame_size > self.max_bytes {
            return;
        }
        while self.current_bytes + frame_size > self.max_bytes && !self.frames.is_empty() {
            if let Some(old) = self.frames.pop_front() {
                self.current_bytes -= old.len();
            }
        }
        self.current_bytes += frame_size;
        self.frames.push_back(frame);
    }

    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let drained: Vec<Vec<u8>> = self.frames.drain(..).collect();
        self.current_bytes = 0;
        drained
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn bytes_used(&self) -> usize {
        self.current_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_drain() {
        let mut buf = RingBuffer::new(1024);
        buf.push(vec![0u8; 100]);
        buf.push(vec![1u8; 100]);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.bytes_used(), 200);

        let frames = buf.drain();
        assert_eq!(frames.len(), 2);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_overflow_drops_oldest() {
        let mut buf = RingBuffer::new(200);
        buf.push(vec![0u8; 100]);
        buf.push(vec![1u8; 100]);
        // Buffer full at 200, pushing 100 more should drop first
        buf.push(vec![2u8; 100]);
        assert_eq!(buf.len(), 2);
        let frames = buf.drain();
        assert_eq!(frames[0], vec![1u8; 100]);
        assert_eq!(frames[1], vec![2u8; 100]);
    }

    #[test]
    fn test_empty_buffer() {
        let buf = RingBuffer::new(1024);
        assert!(buf.is_empty());
        assert_eq!(buf.bytes_used(), 0);
    }

    #[test]
    fn test_oversized_frame_is_discarded() {
        let mut buf = RingBuffer::new(100);
        buf.push(vec![1u8; 101]);
        assert!(buf.is_empty());
        assert_eq!(buf.bytes_used(), 0);
    }
}
