use digest::{generic_array::GenericArray, typenum::U64};

cfg_if::cfg_if! {
    if #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))] {
        extern "C" {
            fn sha256f_compress_c(
                state_ptr: *mut u32,
                blocks_ptr: *const u8,
                num_blocks: usize,
            );
        }
        
        #[inline(always)]
        fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
            // SAFETY: state and blocks have valid pointers and lengths
            unsafe {
                sha256f_compress_c(
                    state.as_mut_ptr(),
                    blocks.as_ptr() as *const u8,
                    blocks.len(),
                );
            }
        }
    } else if #[cfg(feature = "force-soft-compact")] {
        mod soft_compact;
        use soft_compact::compress;
    } else if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(not(feature = "asm"))]
        mod soft;
        #[cfg(feature = "asm")]
        mod soft {
            pub(crate) use sha2_asm::compress256 as compress;
        }
        mod x86;
        use x86::compress;
    } else if #[cfg(all(feature = "asm", target_arch = "aarch64"))] {
        mod soft;
        mod aarch64;
        use aarch64::compress;
    } else if #[cfg(all(feature = "loongarch64_asm", target_arch = "loongarch64"))] {
        mod loongarch64_asm;
        use loongarch64_asm::compress;
    } else {
        mod soft;
        use soft::compress;
    }
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress256(state: &mut [u32; 8], blocks: &[GenericArray<u8, U64>]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; 64];
    let blocks = unsafe { core::slice::from_raw_parts(p, blocks.len()) };
    compress(state, blocks)
}
