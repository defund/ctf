pub mod ot;

pub const BLOCK_SIZE: usize = 16;

pub fn pack_block(bits: &[u16]) -> [u8; BLOCK_SIZE] {
    assert_eq!(bits.len(), BLOCK_SIZE * 8);
    let mut block = [0; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        for j in 0..8 {
            let b = bits[i * 8 + j] as u8;
            assert!(b < 2);
            block[i] |= b << (7 - j);
        }
    }
    block
}

pub fn unpack_block(block: &[u8]) -> [u16; BLOCK_SIZE * 8] {
    assert_eq!(block.len(), BLOCK_SIZE);
    let mut bits = [0; BLOCK_SIZE * 8];
    for i in 0..BLOCK_SIZE {
        for j in 0..8 {
            bits[i * 8 + j] = ((block[i] >> (7 - j)) & 1) as u16;
        }
    }
    bits
}
