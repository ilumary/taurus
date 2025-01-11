use crate::terror;

pub const INITIAL_MAX_DATA: u64 = 0x400;
pub const INITIAL_MAX_DATA_BIDI_STREAM: u64 = 0x400;
pub const INITIAL_MAX_DATA_UNI_STREAM: u64 = 0x400;

pub const MAX_WINDOW_STREAM: u64 = 0x4000;
pub const MAX_WINDOW_CONNECTION: u64 = 0x10000;

#[derive(Default)]
pub struct InitialStreamDataLimits {
    // initial send limit on our side for bidi streams opened by peer
    pub max_stream_data_bidi_local: u64,

    // initial send limit on our side for bidi streams opened by us
    pub max_stream_data_bidi_remote: u64,

    // initial send limit for uni streams opened by us
    pub max_stream_data_uni: u64,
}

#[derive(Default)]
pub struct FlowControl {
    // max data advertised by us to peer
    max_data: u64,

    // indicating a nearly full window
    nearly_full: bool,

    // highest bytes offset received
    len: u64,

    // current window size
    window_size: u64,

    // the maximum size of the window
    max_window_size: u64,
}

impl FlowControl {
    pub fn with_max_data(max_data: u64, max_window_size: u64) -> Self {
        Self {
            max_data,
            nearly_full: false,
            len: 0,
            window_size: max_data,
            max_window_size,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn nearly_full(&self) -> bool {
        self.nearly_full
    }

    pub fn window_size(&self) -> u64 {
        self.window_size
    }

    // validates an incoming packets len against the current window
    pub fn validate(&mut self, off: u64, len: u64) -> Result<(), terror::Error> {
        if self.max_data < off + len {
            return Err(terror::Error::quic_transport_error(
                "peer exceeded flow control recv limit",
                terror::QuicTransportError::FlowControlError,
            ));
        }

        self.len = std::cmp::max(self.len, off + len);

        // if the window is more than 50% full, set nearly_full to true
        self.nearly_full = ((self.max_data - self.len) < self.window_size >> 1) as u8 != 0;

        Ok(())
    }

    // autotunes the window size by at least a factor of 1.5. additional window size is added if
    // the load is low, i.e. the host is not throttling
    pub fn adjust_window_size(&mut self, throttle: bool) {
        println!("old window_size: {}", self.window_size);
        self.window_size = std::cmp::min(
            self.window_size
                + (self.window_size >> 1)
                + ((!throttle as u8) as u64 * (self.window_size >> 1)),
            self.max_window_size,
        );
        println!("new window_size: {}", self.window_size);
    }

    // update and returns new max_data
    pub fn poll_max_data(&mut self) -> u64 {
        self.max_data += self.window_size;
        self.max_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_control_validate_nearly_full() {
        let mut fc = FlowControl::with_max_data(1024, MAX_WINDOW_STREAM);

        fc.validate(512, 128).unwrap();

        assert!(fc.nearly_full);
    }

    #[test]
    fn flow_control_adjust_window_size_throttled() {
        let mut fc = FlowControl::with_max_data(1024, MAX_WINDOW_STREAM);

        fc.adjust_window_size(true);

        assert_eq!(fc.window_size, 1536);
    }

    #[test]
    fn flow_control_adjust_window_size_unthrottled() {
        let mut fc = FlowControl::with_max_data(1024, MAX_WINDOW_STREAM);

        fc.adjust_window_size(false);

        assert_eq!(fc.window_size, 2048);
    }

    #[test]
    fn flow_control_max_window_size() {
        let mut fc = FlowControl::with_max_data(1024, MAX_WINDOW_STREAM);
        fc.window_size = 14_000;

        fc.adjust_window_size(false);

        assert_eq!(fc.window_size, MAX_WINDOW_STREAM);
    }
}
