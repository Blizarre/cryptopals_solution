extern crate log;

use log::debug;
use std::{cmp::min, collections::HashSet};

pub trait ScoringFunction {
    fn score(data: &[u8]) -> Option<f32>;
}

pub struct EnglishLetterFreq();

impl ScoringFunction for EnglishLetterFreq {
    fn score(data: &[u8]) -> Option<f32> {
        let mut letter_stats = [0; 26];

        for c in data {
            if c.is_ascii_alphabetic() {
                letter_stats[c.to_ascii_lowercase() as usize - 'a' as usize] += 1;
            } else if !(c.is_ascii_alphanumeric()
                || c.is_ascii_whitespace()
                || c.is_ascii_punctuation())
            {
                return None;
            }
        }

        let english_letter_stats = [
            0.082, 0.015, 0.028, 0.043, 0.127, 0.022, // F
            0.02, 0.061, 0.07, 0.0015, 0.0077, 0.04, // L
            0.024, 0.067, 0.075, 0.019, 0.00095, 0.06, // R
            0.063, 0.091, 0.028, 0.0098, 0.024, 0.0015, // X
            0.02, 0.00074, // Z
        ];
        let number_of_letters: i32 = letter_stats.iter().sum();
        let letter_stats = letter_stats.map(|a| a as f32 / number_of_letters as f32);
        let ssd = letter_stats
            .iter()
            .zip(english_letter_stats.iter())
            .map(|(a, b)| (a - b).powf(2.0));
        let ssd = 1.0 - ssd.sum::<f32>();

        debug!(
            "[score_english] for {}: ssd {}",
            String::from_utf8(data.to_vec()).unwrap(),
            ssd
        );

        Some(ssd)
    }
}

pub struct EnglishWordFreq();

impl ScoringFunction for EnglishWordFreq {
    fn score(data: &[u8]) -> Option<f32> {
        // https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
        // e, a, r, i, o, t makes about 50% of all the letters found in a typical english text
        let mut letters_bucket1 = 0;

        // the remaining letters make up the other 50%
        let mut letters_bucket2 = 0;

        for b in data {
            if !(b.is_ascii_alphanumeric() || b.is_ascii_whitespace() || b.is_ascii_punctuation()) {
                return None;
            }
            if b.is_ascii_alphabetic() {
                if [b'e', b'a', b'r', b'i', b'o', b't'].contains(&b.to_ascii_lowercase()) {
                    letters_bucket1 += 1;
                } else {
                    letters_bucket2 += 1;
                }
            }
        }

        // 0 is perfect, 0.5 is worst
        let frequency_score: f32 =
            (letters_bucket1 as f32 / (letters_bucket1 + letters_bucket2) as f32 - 0.5).abs();
        // 0 is worst, 1 is perfect
        let frequency_score = 1.0 - 2.0 * frequency_score;

        let words: HashSet<String> = data
            .split(|c| c.is_ascii_whitespace() | c.is_ascii_punctuation())
            .map(|word| String::from_utf8(word.to_ascii_lowercase()).unwrap())
            .collect();

        // Most ommon words
        let common_words: HashSet<String> = HashSet::from_iter(
            ["the", "to", "of", "and", "a", "in", "that", "have", "I"]
                .iter()
                .map(|s| s.to_string()),
        );
        // 0 is worst, 1 is perfect
        let common_word_score =
            words.intersection(&common_words).count() as f32 / common_words.len() as f32;

        let words_length: Vec<usize> = words.iter().map(|w| w.len()).filter(|l| *l > 0).collect();
        let average_word_length =
            words_length.iter().sum::<usize>() as f32 / words_length.len() as f32;
        // Let's pick an average word length of 4.5
        // https://www.researchgate.net/figure/Dynamics-of-average-length-of-short-and-long-words_fig2_230764201
        // 0.0 for an average word length of 9, 1.0 for 4.5.
        // We accept that it is unbounded in the negative for large words because average word length >> 9 chars are highly unlikely
        let average_word_length_score = 1.0 - (average_word_length - 4.5).abs() / 4.5;

        debug!(
            "[score_english] for {}: cm {} fr {} wl {}",
            String::from_utf8(data.to_vec()).unwrap(),
            common_word_score,
            frequency_score,
            average_word_length_score
        );

        Some(common_word_score + frequency_score + average_word_length_score)
    }
}
pub struct DecodingResult {
    pub score: f32,
    pub key: u8,
    pub decoded_content: Vec<u8>,
}

pub fn break_xor_single_char<T: ScoringFunction>(data: &[u8]) -> Option<DecodingResult> {
    let mut max_score = f32::MIN;
    let mut result: Option<DecodingResult> = None;

    for key in 0u8..=255u8 {
        let decoded: Vec<u8> = data.iter().map(|c| c ^ key).collect();
        let score = T::score(&decoded);

        if let Some(score) = score {
            if score > max_score {
                debug!(
                    "[decode_xor] Better score: {}: {}",
                    score,
                    String::from_utf8(decoded.clone()).unwrap()
                );
                result = Some(DecodingResult { score: score, key: key, decoded_content: decoded });
                max_score = score;
            }
        }
    }
    result
}

pub fn hamming_distance(block1: &[u8], block2: &[u8]) -> u32 {
    let (short, long) = if block2.len() > block1.len() {
        (block1.iter(), block2.iter())
    } else {
        (block2.iter(), block1.iter())
    };

    let mut distance = 0;
    for (c1, c2) in long.zip(short.chain([0].iter().cycle())) {
        distance += (c1 ^ c2).count_ones();
    }
    distance
}

pub fn find_xor_keysize(data: &[u8]) -> Option<usize> {
    let max_key_size = min(40, data.len() / 2);

    // Cannot use an iterator.min safely because f32 doesn't implement Ord
    let mut min_score = None;
    let mut min_key_size = None;

    for key_size in 2..=max_key_size {
        let iter = data.iter();
        let block1 = iter.clone().take(key_size).copied().collect::<Vec<u8>>();
        let block2 = iter
            .skip(key_size)
            .take(key_size)
            .copied()
            .collect::<Vec<u8>>();
        let score = hamming_distance(&block1, &block2) as f32 / key_size as f32;
        debug!("[find_xor_keysize] size: {:?}, score {:?}", key_size, score);

        if let Some(previous_min_score) = min_score {
            if score < previous_min_score {
                min_score = Some(score);
                min_key_size = Some(key_size);
            }
        } else {
            min_score = Some(score);
            min_key_size = Some(key_size);
        }
    }
    debug!(
        "[find_xor_keysize] best size: {:?}, best score {:?}",
        min_key_size, min_score
    );
    min_key_size
}

fn transpose_blocks(data: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    blocks.resize_with(key_size, Vec::new);
    data.chunks(key_size)
        .for_each(|chunk| blocks.iter_mut().zip(chunk).for_each(|(b, c)| b.push(*c)));
    blocks
}

pub fn find_key_block_xor(data: &[u8], key_size: usize) -> Option<Vec<u8>> {
    transpose_blocks(data, key_size)
        .iter()
        .map(|b| break_xor_single_char::<EnglishLetterFreq>(b))
        .map(|d| d.map(|d|d.key))
        .collect::<Option<Vec<u8>>>()
}

#[cfg(test)]
mod tests {
    use crate::decrypt::*;

    #[test]
    fn test_englishwordfreq() {
        assert!(
            EnglishWordFreq::score("Hello world, This is a weird test".as_bytes()).unwrap()
                > EnglishWordFreq::score("aaaBBB".as_bytes()).unwrap()
        );
        assert!(
            EnglishWordFreq::score("Hello world. This is not a test".as_bytes()).unwrap()
                > EnglishWordFreq::score("yesyesyesyes".as_bytes()).unwrap()
        );
        assert!(
            EnglishWordFreq::score("Hello world. This is not a test".as_bytes()).unwrap()
                > EnglishWordFreq::score("CCCvdd jdsdsdg suy yes of DDDDNNN".as_bytes()).unwrap()
        );
        assert!(EnglishWordFreq::score("Hello\0world".as_bytes()).is_none());
    }

    #[test]
    fn test_englishletterfreq() {
        assert!(
            EnglishLetterFreq::score("Hello world, This is a weird test".as_bytes()).unwrap()
                > EnglishLetterFreq::score("aaaBBB".as_bytes()).unwrap()
        );
        assert!(
            EnglishLetterFreq::score("Hello world. This is not a test".as_bytes()).unwrap()
                > EnglishLetterFreq::score("yesyesyesyes".as_bytes()).unwrap()
        );
        assert!(
            EnglishLetterFreq::score("Hello world. This is not a test".as_bytes()).unwrap()
                > EnglishLetterFreq::score("CCCvdd jdsdsdg suy yes of DDDDNNN".as_bytes()).unwrap()
        );
        assert!(EnglishLetterFreq::score("Hello\0world".as_bytes()).is_none());
    }

    #[test]
    fn test_decode_xor_success_englishwordfreq() {
        let encrypted: Vec<u8> = vec![
            0x03, 0x2E, 0x2E, 0x62, 0x2A, 0x37, 0x2F, 0x23, 0x2C, 0x62, 0x20, 0x27, 0x2B, 0x2C,
            0x25, 0x31, 0x62, 0x23, 0x30, 0x27, 0x62, 0x20, 0x2D, 0x30, 0x2C, 0x62, 0x24, 0x30,
            0x27, 0x27, 0x62, 0x23, 0x2C, 0x26, 0x62, 0x27, 0x33, 0x37, 0x23, 0x2E, 0x62, 0x2B,
            0x2C, 0x62, 0x26, 0x2B, 0x25, 0x2C, 0x2B, 0x36, 0x3B, 0x62, 0x23, 0x2C, 0x26, 0x62,
            0x30, 0x2B, 0x25, 0x2A, 0x36, 0x31, 0x6C, 0x62, 0x16, 0x2A, 0x27, 0x3B, 0x62, 0x23,
            0x30, 0x27, 0x62, 0x27, 0x2C, 0x26, 0x2D, 0x35, 0x27, 0x26, 0x62, 0x35, 0x2B, 0x36,
            0x2A, 0x62, 0x30, 0x27, 0x23, 0x31, 0x2D, 0x2C, 0x62, 0x23, 0x2C, 0x26, 0x62, 0x21,
            0x2D, 0x2C, 0x31, 0x21, 0x2B, 0x27, 0x2C, 0x21, 0x27, 0x62, 0x23, 0x2C, 0x26, 0x62,
            0x31, 0x2A, 0x2D, 0x37, 0x2E, 0x26, 0x62, 0x23, 0x21, 0x36, 0x62, 0x36, 0x2D, 0x35,
            0x23, 0x30, 0x26, 0x31, 0x62, 0x2D, 0x2C, 0x27, 0x62, 0x23, 0x2C, 0x2D, 0x36, 0x2A,
            0x27, 0x30, 0x62, 0x2B, 0x2C, 0x62, 0x23, 0x62, 0x31, 0x32, 0x2B, 0x30, 0x2B, 0x36,
            0x62, 0x2D, 0x24, 0x62, 0x20, 0x30, 0x2D, 0x36, 0x2A, 0x27, 0x30, 0x2A, 0x2D, 0x2D,
            0x26, 0x6C,
        ];
        let decrypted = break_xor_single_char::<EnglishWordFreq>(&encrypted);
        assert!(decrypted.is_some());
        let decrypted = decrypted.unwrap();

        assert_eq!(
        String::from_utf8(decrypted.decoded_content).unwrap(),
        "All human beings are born free and equal in dignity and rights. ".to_owned() +
        "They are endowed with reason and conscience and should act towards one another in a spirit of brotherhood."
    );
    }

    #[test]
    fn test_decode_xor_failure_englishwordfreq() {
        let encrypted: Vec<u8> = (0..255).collect();
        let decrypted = break_xor_single_char::<EnglishWordFreq>(&encrypted);
        assert!(decrypted.is_none());
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test", b"this is a test"), 0);
        assert_eq!(hamming_distance(b"", &[0b1, 0b1]), 2);
        assert_eq!(hamming_distance(&[0b11, 0b11], &[0b11, 0b11]), 0);
        assert_eq!(hamming_distance(&[], &[0b1111, 0b11]), 6);
        assert_eq!(hamming_distance(&[0b1111, 0b11], &[]), 6);
    }

    #[test]
    fn test_find_xor_keysize() {
        assert_eq!(find_xor_keysize(&[]), None);
        assert_eq!(find_xor_keysize(&[0, 1, 0, 2]), Some(2));
        assert_eq!(find_xor_keysize(&[0, 1, 2, 0, 1, 2]), Some(3));
        assert_eq!(find_xor_keysize(&[0, 1, 2, 3, 0, 1, 2, 3]), Some(4));
        assert_eq!(find_xor_keysize(&[0, 1, 2, 3, 0, 1, 2, 2]), Some(4));
    }

    #[test]
    fn test_transpose() {
        assert_eq!(
            transpose_blocks(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3),
            vec![vec![1, 4, 7, 10], vec![2, 5, 8], vec![3, 6, 9],]
        );
        assert_eq!(transpose_blocks(&[], 3), vec![vec![], vec![], vec![]]);
        assert_eq!(
            transpose_blocks(&[1, 2, 3], 3),
            vec![vec![1], vec![2], vec![3]]
        );
        assert_eq!(
            transpose_blocks(&[1, 2, 3, 4], 3),
            vec![vec![1, 4], vec![2], vec![3]]
        );
        assert_eq!(transpose_blocks(&[1], 3), vec![vec![1], vec![], vec![]]);
    }
}
