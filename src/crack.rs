use std::{collections::HashMap, error::Error, fmt::Display};

#[derive(Debug)]
pub struct InternalError(String);

impl Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for InternalError {}

pub fn crack_ecb(
    generator: impl Fn(&[u8]) -> Result<Vec<u8>, Box<dyn Error>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let block_size = 16;
    let number_of_blocks = generator(&[])?.len() / block_size;

    let mut plaintexts: Vec<Vec<u8>> = vec![];
    // We are basically going to loop over each block, solving them one after the other
    for block_idx in 0..number_of_blocks {
        let mut bait_block: Vec<u8> = if !plaintexts.is_empty() {
            plaintexts.last().cloned().unwrap()
        } else {
            vec![0; block_size]
        };
        // The trick is that if you know the left part of a message, and can prefix an arbitrary
        // block of data, then you can deduce the next byte in the message. To do that you will
        // need to know the content of a plain text block, and have the ability to shift the entire
        // message left, to bring in the bytes of the next block, one at a time. Every time you
        // add a new byte, there are only 256 possible values for that byte, and you know the rest
        // of the block, so you can compute the cyphertext for each of them and compare them with
        // the one from the message itself.
        let mut plain_block = vec![];
        for _ in 0..bait_block.len() {
            bait_block.remove(0);
            let mut candidates = HashMap::<Vec<u8>, u8>::new();
            for c in 0..=255u8 {
                let mut candidate = [bait_block.clone(), plain_block.clone()].concat();
                candidate.push(c);
                let encrypted = generator(&candidate)?.get(0..16).unwrap().to_owned();
                candidates.insert(encrypted, c);
            }
            let actual = generator(&bait_block)?
                .get(plaintexts.len() * 16..plaintexts.len() * 16 + 16)
                .unwrap()
                .to_owned();
            if !candidates.contains_key(&actual) {
                // If we are on the last block, we are hitting the dynamic part of the message
                // (padding)
                if block_idx == number_of_blocks - 1 {
                    plain_block.pop();
                    plaintexts.push(plain_block);
                    return Ok(plaintexts.concat());
                }
                return Err(InternalError(
                    "Could not find a matching encrypted message".to_string(),
                )
                .into());
            }
            plain_block.push(candidates[&actual]);
        }
        plaintexts.push(plain_block.clone());
    }
    Ok(plaintexts.concat())
}
