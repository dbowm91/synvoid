use crate::maps::{TokenBucketState, TOKEN_BUCKET_INBOUND, TOKEN_BUCKET_OUTBOUND};
use aya_ebpf::helpers::bpf_ktime_get_ns;

/// Token bucket rate limiting for ICMP.
/// # Safety
/// The `bpf_ktime_get_ns` helper is safe to call; pointer dereferences are bounds-checked.

const NSEC_PER_SEC: u64 = 1_000_000_000;
const MAX_TOKENS_TO_ADD: u64 = 1_000_000;

#[inline(always)]
pub fn try_consume_inbound(packets_per_second: u32, burst: u32) -> bool {
    try_consume_impl(&TOKEN_BUCKET_INBOUND, packets_per_second, burst)
}

#[inline(always)]
pub fn try_consume_outbound(packets_per_second: u32, burst: u32) -> bool {
    try_consume_impl(&TOKEN_BUCKET_OUTBOUND, packets_per_second, burst)
}

#[inline(always)]
fn try_consume_impl(
    bucket_map: &aya_ebpf::maps::PerCpuArray<TokenBucketState>,
    packets_per_second: u32,
    burst: u32,
) -> bool {
    if packets_per_second == 0 || burst == 0 {
        return false;
    }

    let now_ns = unsafe { bpf_ktime_get_ns() };
    let rate = packets_per_second as u64;
    let capacity = burst as u64;

    let ptr = bucket_map.get_ptr_mut(0);
    let state = match ptr {
        Some(s) => unsafe { &mut *s },
        None => return false,
    };

    let last_update = state.last_update_ns;
    let mut tokens = state.tokens;

    if last_update > 0 && now_ns > last_update {
        let elapsed_ns = now_ns.saturating_sub(last_update);
        let tokens_to_add = (elapsed_ns * rate) / NSEC_PER_SEC;
        let tokens_to_add = tokens_to_add.min(MAX_TOKENS_TO_ADD);
        tokens = tokens.saturating_add(tokens_to_add).min(capacity);
    }

    if tokens > 0 {
        state.tokens = tokens.saturating_sub(1);
        state.last_update_ns = now_ns;
        true
    } else {
        state.last_update_ns = now_ns;
        false
    }
}
