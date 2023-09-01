extern crate env_logger;
extern crate openssl;

mod base64;
mod block;
mod decrypt;
mod encrypt;
mod ffi_openssl;
mod hex;

use std::fs::File;
use std::io::Read;

use log::info;

use crate::base64::{from_base64, load_base64_file, to_base64};
use crate::block::{add_padding, decrypt_cbc, decrypt_ecb, encrypt_cbc, xor, BlockSize};
use crate::decrypt::{
    break_xor_single_char, find_key_block_xor, find_likely_xor_keysizes, hamming_distance,
    EnglishWordFreq,
};
use crate::encrypt::encode_xor;
use crate::hex::from_hex;

fn main() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    set1();

    set2();
}

fn set1() {
    info!("Set1 Challenge 1");

    assert_eq!(
            to_base64(&from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap()),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );

    info!("Set1 Challenge 2");

    assert_eq!(
        xor(
            &from_hex("1c0111001f010100061a024b53535009181c").unwrap(),
            &from_hex("686974207468652062756c6c277320657965").unwrap()
        )
        .unwrap(),
        from_hex("746865206b696420646f6e277420706c6179").unwrap()
    );

    info!("Set1 Challenge3");

    assert_eq!(
        String::from_utf8(
            break_xor_single_char::<EnglishWordFreq>(
                &from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                    .unwrap()
            )
            .unwrap()
            .decoded_content
        )
        .unwrap(),
        "Cooking MC's like a pound of bacon"
    );

    info!("Set1 Challenge 4");

    let mut data = String::new();
    File::open("data/4.txt")
        .and_then(|mut f| f.read_to_string(&mut data))
        .unwrap();

    let mut max_score = f32::MIN;
    let mut best_line = String::new();

    for line in data.split('\n') {
        let decoded = break_xor_single_char::<EnglishWordFreq>(&from_hex(line).unwrap());
        if let Some(decoded) = decoded {
            if decoded.score > max_score {
                max_score = decoded.score;
                best_line = String::from_utf8(decoded.decoded_content).unwrap();
            }
        }
    }
    assert_eq!(best_line, "Now that the party is jumping\n");

    info!("Set1 Challenge 5");

    assert_eq!(
        encode_xor(
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            b"ICE"
        ),
        Ok(vec![
            11, 54, 55, 39, 42, 43, 46, 99, 98, 44, 46, 105, 105, 42, 35, 105, 58, 42, 60, 99, 36,
            32, 45, 98, 61, 99, 52, 60, 42, 38, 34, 99, 36, 39, 39, 101, 39, 42, 40, 43, 47, 32,
            67, 10, 101, 46, 44, 101, 42, 49, 36, 51, 58, 101, 62, 43, 32, 39, 99, 12, 105, 43, 32,
            40, 49, 101, 40, 99, 38, 48, 46, 39, 40, 47
        ])
    );

    info!("Set1 Challenge 6");

    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);

    let data = load_base64_file("6").unwrap();

    let key_sizes = find_likely_xor_keysizes(&data);
    let mut decoded = None;
    for key_size in key_sizes {
        info!("Checking key size {}", key_size);
        if let Some(key) = find_key_block_xor(&data, key_size) {
            let decoded_data = data
                .chunks(key_size)
                .flat_map(|d| encode_xor(d, &key))
                .flatten()
                .collect::<Vec<u8>>();
            decoded = Some(String::from_utf8(decoded_data).unwrap());
            break;
        }
    }
    assert_eq!(
        decoded,
        Some(
            "I'm back and I'm ringin' the bell \n".to_string()
                + "A rockin' on the mike while the fly girls yell \n"
                + "In ecstasy in the back of me \n"
                + "Well that's my DJ Deshay cuttin' all them Z's \n"
                + "Hittin' hard and the girlies goin' crazy \n"
                + "Vanilla's on the mike, man I'm not lazy. \n"
                + "\n"
                + "I'm lettin' my drug kick in \n"
                + "It controls my mouth and I begin \n"
                + "To just let it flow, let my concepts go \n"
                + "My posse's to the side yellin', Go Vanilla Go! \n"
                + "\n"
                + "Smooth 'cause that's the way I will be \n"
                + "And if you don't give a damn, then \n"
                + "Why you starin' at me \n"
                + "So get off 'cause I control the stage \n"
                + "There's no dissin' allowed \n"
                + "I'm in my own phase \n"
                + "The girlies sa y they love me and that is ok \n"
                + "And I can dance better than any kid n' play \n"
                + "\n"
                + "Stage 2 -- Yea the one ya' wanna listen to \n"
                + "It's off my head so let the beat play through \n"
                + "So I can funk it up and make it sound good \n"
                + "1-2-3 Yo -- Knock on some wood \n"
                + "For good luck, I like my rhymes atrocious \n"
                + "Supercalafragilisticexpialidocious \n"
                + "I'm an effect and that you can bet \n"
                + "I can take a fly girl and make her wet. \n"
                + "\n"
                + "I'm like Samson -- Samson to Delilah \n"
                + "There's no denyin', You can try to hang \n"
                + "But you'll keep tryin' to get my style \n"
                + "Over and over, practice makes perfect \n"
                + "But not if you're a loafer. \n"
                + "\n"
                + "You'll get nowhere, no place, no time, no girls \n"
                + "Soon -- Oh my God, homebody, you probably eat \n"
                + "Spaghetti with a spoon! Come on and say it! \n"
                + "\n"
                + "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
                + "Intoxicating so you stagger like a wino \n"
                + "So punks stop trying and girl stop cryin' \n"
                + "Vanilla Ice is sellin' and you people are buyin' \n"
                + "'Cause why the freaks are jockin' like Crazy Glue \n"
                + "Movin' and groovin' trying to sing along \n"
                + "All through the ghetto groovin' this here song \n"
                + "Now you're amazed by the VIP posse. \n"
                + "\n"
                + "Steppin' so hard like a German Nazi \n"
                + "Startled by the bases hittin' ground \n"
                + "There's no trippin' on mine, I'm just gettin' down \n"
                + "Sparkamatic, I'm hangin' tight like a fanatic \n"
                + "You trapped me once and I thought that \n"
                + "You might have it \n"
                + "So step down and lend me your ear \n"
                + "'89 in my time! You, '90 is my year. \n"
                + "\n"
                + "You're weakenin' fast, YO! and I can tell it \n"
                + "Your body's gettin' hot, so, so I can smell it \n"
                + "So don't be mad and don't be sad \n"
                + "'Cause the lyrics belong to ICE, You can call me Dad \n"
                + "You're pitchin' a fit, so step back and endure \n"
                + "Let the witch doctor, Ice, do the dance to cure \n"
                + "So come up close and don't be square \n"
                + "You wanna battle me -- Anytime, anywhere \n"
                + "\n"
                + "You thought that I was weak, Boy, you're dead wrong \n"
                + "So come on, everybody and sing this song \n"
                + "\n"
                + "Say -- Play that funky music Say, go white boy, go white boy go \n"
                + "play that funky music Go white boy, go white boy, go \n"
                + "Lay down and boogie and play that funky music till you die. \n"
                + "\n"
                + "Play that funky music Come on, Come on, let me hear \n"
                + "Play that funky music white boy you say it, say it \n"
                + "Play that funky music A little louder now \n"
                + "Play that funky music, white boy Come on, Come on, Come on \n"
                + "Play that funky music \n"
                + ""
        )
    );

    info!("Set1 Challenge 7");

    let ciphertext = load_base64_file("7").unwrap();
    let plaintext = decrypt_ecb(&ciphertext, "YELLOW SUBMARINE".as_bytes()).unwrap();

    assert_eq!(
        String::from_utf8(plaintext),
        Ok("I'm back and I'm ringin' the bell \n".to_owned()
            + "A rockin' on the mike while the fly girls yell \n"
            + "In ecstasy in the back of me \n"
            + "Well that's my DJ Deshay cuttin' all them Z's \n"
            + "Hittin' hard and the girlies goin' crazy \n"
            + "Vanilla's on the mike, man I'm not lazy. \n"
            + "\n"
            + "I'm lettin' my drug kick in \n"
            + "It controls my mouth and I begin \n"
            + "To just let it flow, let my concepts go \n"
            + "My posse's to the side yellin', Go Vanilla Go! \n"
            + "\n"
            + "Smooth 'cause that's the way I will be \n"
            + "And if you don't give a damn, then \n"
            + "Why you starin' at me \n"
            + "So get off 'cause I control the stage \n"
            + "There's no dissin' allowed \n"
            + "I'm in my own phase \n"
            + "The girlies sa y they love me and that is ok \n"
            + "And I can dance better than any kid n' play \n"
            + "\n"
            + "Stage 2 -- Yea the one ya' wanna listen to \n"
            + "It's off my head so let the beat play through \n"
            + "So I can funk it up and make it sound good \n"
            + "1-2-3 Yo -- Knock on some wood \n"
            + "For good luck, I like my rhymes atrocious \n"
            + "Supercalafragilisticexpialidocious \n"
            + "I'm an effect and that you can bet \n"
            + "I can take a fly girl and make her wet. \n"
            + "\n"
            + "I'm like Samson -- Samson to Delilah \n"
            + "There's no denyin', You can try to hang \n"
            + "But you'll keep tryin' to get my style \n"
            + "Over and over, practice makes perfect \n"
            + "But not if you're a loafer. \n"
            + "\n"
            + "You'll get nowhere, no place, no time, no girls \n"
            + "Soon -- Oh my God, homebody, you probably eat \n"
            + "Spaghetti with a spoon! Come on and say it! \n"
            + "\n"
            + "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
            + "Intoxicating so you stagger like a wino \n"
            + "So punks stop trying and girl stop cryin' \n"
            + "Vanilla Ice is sellin' and you people are buyin' \n"
            + "'Cause why the freaks are jockin' like Crazy Glue \n"
            + "Movin' and groovin' trying to sing along \n"
            + "All through the ghetto groovin' this here song \n"
            + "Now you're amazed by the VIP posse. \n"
            + "\n"
            + "Steppin' so hard like a German Nazi \n"
            + "Startled by the bases hittin' ground \n"
            + "There's no trippin' on mine, I'm just gettin' down \n"
            + "Sparkamatic, I'm hangin' tight like a fanatic \n"
            + "You trapped me once and I thought that \n"
            + "You might have it \n"
            + "So step down and lend me your ear \n"
            + "'89 in my time! You, '90 is my year. \n"
            + "\n"
            + "You're weakenin' fast, YO! and I can tell it \n"
            + "Your body's gettin' hot, so, so I can smell it \n"
            + "So don't be mad and don't be sad \n"
            + "'Cause the lyrics belong to ICE, You can call me Dad \n"
            + "You're pitchin' a fit, so step back and endure \n"
            + "Let the witch doctor, Ice, do the dance to cure \n"
            + "So come up close and don't be square \n"
            + "You wanna battle me -- Anytime, anywhere \n"
            + "\n"
            + "You thought that I was weak, Boy, you're dead wrong \n"
            + "So come on, everybody and sing this song \n"
            + "\n"
            + "Say -- Play that funky music Say, go white boy, go white boy go \n"
            + "play that funky music Go white boy, go white boy, go \n"
            + "Lay down and boogie and play that funky music till you die. \n"
            + "\n"
            + "Play that funky music Come on, Come on, let me hear \n"
            + "Play that funky music white boy you say it, say it \n"
            + "Play that funky music A little louder now \n"
            + "Play that funky music, white boy Come on, Come on, Come on \n"
            + "Play that funky music \n"
            + "")
    );

    info!("Set1 Challenge 8");

    let mut data = String::new();
    File::open("data/8.txt")
        .and_then(|mut f| f.read_to_string(&mut data))
        .unwrap();

    // ECB Will encode 2 identical strings into two identical cyphers.
    // Therefore if we find 2 identical cyphers then it is very, very, very likely that
    // this is because we are using ECB, other encoding schemes should return pseudo-random
    // cyphers which are very unlikely to match
    let mut found: Option<&str> = None;
    for line in data.trim().split('\n') {
        let decoded = from_base64(line).unwrap();
        let li = decoded
            .as_slice()
            .chunks(BlockSize::AES_BLK_SZ_USIZE)
            .collect::<Vec<&[u8]>>();
        for (index, val1) in li.iter().enumerate() {
            for val2 in &li[..index] {
                if val1 == val2 {
                    found = Some(line);
                };
            }
        }
    }
    assert_eq!(found, Some("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"));
}

fn set2() {
    info!("Set1 Challenge 9");

    assert_eq!(
        add_padding(b"YELLOW SUBMARINE", BlockSize::new(20).unwrap()),
        Ok(Vec::from(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_ref()))
    );

    info!("Set1 Challenge 10");

    let ciphertext = load_base64_file("10").unwrap();
    let iv = [0; 16];
    let key = b"YELLOW SUBMARINE";

    let plaintext = decrypt_cbc(&ciphertext, &iv, key).unwrap();
    let ciphertext_from_plain = encrypt_cbc(&plaintext, &iv, key).unwrap();

    assert_eq!(ciphertext_from_plain, ciphertext);

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        "I'm back and I'm ringin' the bell \n".to_owned()
            + ""
            + "A rockin' on the mike while the fly girls yell \n"
            + "In ecstasy in the back of me \n"
            + "Well that's my DJ Deshay cuttin' all them Z's \n"
            + "Hittin' hard and the girlies goin' crazy \n"
            + "Vanilla's on the mike, man I'm not lazy. \n"
            + "\n"
            + "I'm lettin' my drug kick in \n"
            + "It controls my mouth and I begin \n"
            + "To just let it flow, let my concepts go \n"
            + "My posse's to the side yellin', Go Vanilla Go! \n"
            + "\n"
            + "Smooth 'cause that's the way I will be \n"
            + "And if you don't give a damn, then \n"
            + "Why you starin' at me \n"
            + "So get off 'cause I control the stage \n"
            + "There's no dissin' allowed \n"
            + "I'm in my own phase \n"
            + "The girlies sa y they love me and that is ok \n"
            + "And I can dance better than any kid n' play \n"
            + "\n"
            + "Stage 2 -- Yea the one ya' wanna listen to \n"
            + "It's off my head so let the beat play through \n"
            + "So I can funk it up and make it sound good \n"
            + "1-2-3 Yo -- Knock on some wood \n"
            + "For good luck, I like my rhymes atrocious \n"
            + "Supercalafragilisticexpialidocious \n"
            + "I'm an effect and that you can bet \n"
            + "I can take a fly girl and make her wet. \n"
            + "\n"
            + "I'm like Samson -- Samson to Delilah \n"
            + "There's no denyin', You can try to hang \n"
            + "But you'll keep tryin' to get my style \n"
            + "Over and over, practice makes perfect \n"
            + "But not if you're a loafer. \n"
            + "\n"
            + "You'll get nowhere, no place, no time, no girls \n"
            + "Soon -- Oh my God, homebody, you probably eat \n"
            + "Spaghetti with a spoon! Come on and say it! \n"
            + "\n"
            + "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
            + "Intoxicating so you stagger like a wino \n"
            + "So punks stop trying and girl stop cryin' \n"
            + "Vanilla Ice is sellin' and you people are buyin' \n"
            + "'Cause why the freaks are jockin' like Crazy Glue \n"
            + "Movin' and groovin' trying to sing along \n"
            + "All through the ghetto groovin' this here song \n"
            + "Now you're amazed by the VIP posse. \n"
            + "\n"
            + "Steppin' so hard like a German Nazi \n"
            + "Startled by the bases hittin' ground \n"
            + "There's no trippin' on mine, I'm just gettin' down \n"
            + "Sparkamatic, I'm hangin' tight like a fanatic \n"
            + "You trapped me once and I thought that \n"
            + "You might have it \n"
            + "So step down and lend me your ear \n"
            + "'89 in my time! You, '90 is my year. \n"
            + "\n"
            + "You're weakenin' fast, YO! and I can tell it \n"
            + "Your body's gettin' hot, so, so I can smell it \n"
            + "So don't be mad and don't be sad \n"
            + "'Cause the lyrics belong to ICE, You can call me Dad \n"
            + "You're pitchin' a fit, so step back and endure \n"
            + "Let the witch doctor, Ice, do the dance to cure \n"
            + "So come up close and don't be square \n"
            + "You wanna battle me -- Anytime, anywhere \n"
            + "\n"
            + "You thought that I was weak, Boy, you're dead wrong \n"
            + "So come on, everybody and sing this song \n"
            + "\n"
            + "Say -- Play that funky music Say, go white boy, go white boy go \n"
            + "play that funky music Go white boy, go white boy, go \n"
            + "Lay down and boogie and play that funky music till you die. \n"
            + "\n"
            + "Play that funky music Come on, Come on, let me hear \n"
            + "Play that funky music white boy you say it, say it \n"
            + "Play that funky music A little louder now \n"
            + "Play that funky music, white boy Come on, Come on, Come on \n"
            + "Play that funky music \n"
            + ""
    );
}
