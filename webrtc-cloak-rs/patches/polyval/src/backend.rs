cpubits::cfg_if! {
    if #[cfg(all(
        any(target_arch = "aarch64", target_arch = "x86_64", target_arch = "x86"),
        not(polyval_backend = "soft")
    ))] {
        mod intrinsics;
        pub(crate) use intrinsics::{State, backend_name, hardware_accelerated};
    } else {
        // "soft" pure Rust portable fallback implementation for other targets
        mod soft;
        pub(crate) use soft::State;

        #[inline]
        pub(crate) fn hardware_accelerated() -> bool {
            false
        }

        #[inline]
        pub(crate) fn backend_name() -> &'static str {
            "soft"
        }
    }
}
