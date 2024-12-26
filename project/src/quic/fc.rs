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
    max_data: u64,

    nearly_full: bool,
}

impl FlowControl {}
