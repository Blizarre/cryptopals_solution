use log::info;
use rand::Rng;

use crate::aes::{decrypt_cbc, encrypt_cbc, encrypt_ecb, oracle, unknown_encryption, Protocol};
use crate::base64::{from_base64, load_base64_file};
use crate::block::{add_padding, BlockSize};
use crate::crack::crack_ecb;

pub fn run() {
    info!("Set2 Challenge 9");

    assert_eq!(
        add_padding(b"YELLOW SUBMARINE", BlockSize::new(20).unwrap()),
        Ok(Vec::from(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_ref()))
    );

    info!("Set2 Challenge 10");

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

    info!("Set2 Challenge 11");

    for _ in 0..30 {
        // This is super clunky but it works to extract the real protocol without telling
        // the oracle function
        let mut real_protocol = Protocol::Cbc;
        let protocol = oracle(|x| {
            let res = unknown_encryption(x).unwrap();
            real_protocol = res.0;
            res.1
        });
        assert_eq!(protocol, real_protocol);
    }

    info!("Set2 Challenge 12");
    let secret_message = from_base64(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkga\
        GFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvI\
        HNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
    )
    .unwrap();

    let mut rng = rand::thread_rng();

    let unknown_key: [u8; 16] = rng.gen();
    let random_ecb = |data: &[u8]| {
        return encrypt_ecb(
            [data, secret_message.as_slice()].concat().as_slice(),
            &unknown_key,
        );
    };

    let extracted_message = crack_ecb(random_ecb).unwrap();
    assert_eq!(
        String::from_utf8(extracted_message).unwrap(),
        String::from_utf8(secret_message).unwrap()
    );
}

#[cfg(test)]
mod tests {
    use crate::set2::run;
    #[test]
    fn test() {
        run();
    }
}
