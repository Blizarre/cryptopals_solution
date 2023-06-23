extern crate log;

use log::debug;
use std::collections::HashSet;

fn score_english(data: &[u8]) -> f32 {
    // https://www3.nd.edu/~busiforc/handouts/cryptography/letterfrequencies.html
    // e, a, r, i, o, t makes about 50% of all the letters found in a typical english text
    let mut letters_bucket1 = 0;

    // the remaining letters make up the other 50%
    let mut letters_bucket2 = 0;

    for b in data {
        if !(b.is_ascii_alphanumeric() || b.is_ascii_whitespace() || b.is_ascii_punctuation()) {
            return -1.0;
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
    let average_word_length = words_length.iter().sum::<usize>() as f32 / words_length.len() as f32;
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

    common_word_score + frequency_score + average_word_length_score
}

pub fn decode_xor(data: &[u8]) -> Vec<u8> {
    let mut max_score = f32::MIN;
    let mut best_candidate = vec![];

    for key in 0u8..=255u8 {
        let decoded: Vec<u8> = data.iter().map(|c| c ^ key).collect();
        let score = score_english(&decoded);

        if score > max_score {
            debug!(
                "[decode_xor] Better score: {}: {}",
                score,
                String::from_utf8(decoded.clone()).unwrap()
            );
            best_candidate = decoded;
            max_score = score;
        }
    }
    best_candidate
}

#[test]
fn test_score_english() {
    assert!(
        score_english("Hello world, This is a weird test".as_bytes())
            > score_english("aaaBBB".as_bytes())
    );
    assert!(
        score_english("Hello world. This is not a test".as_bytes())
            > score_english("yesyesyesyes".as_bytes())
    );
    assert!(
        score_english("Hello world. This is not a test".as_bytes())
            > score_english("CCCvdd jdsdsdg suy yes of DDDDNNN".as_bytes())
    );
    assert!(score_english("aaaBBBCCC".as_bytes()) > score_english("Hello\0world".as_bytes()));
}
