use std::{error::Error, fmt, fs::File, io::Read};

// https://datatracker.ietf.org/doc/html/rfc4648#section-4
fn to_base64_char(b: u8) -> char {
    match b {
        0..=25 => (b + b'A') as char,
        26..=51 => (b - 26 + b'a') as char,
        52..=61 => (b - 52 + b'0') as char,
        62 => '+',
        63 => '/',
        _ => panic!("Invalid base64 character"), // TODO: don't panic!
    }
}

#[derive(Debug)]
pub struct InvalidBase64Char {
    character: char,
}

impl fmt::Display for InvalidBase64Char {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid Base64 data, char {} is invalid", self.character)
    }
}

impl Error for InvalidBase64Char {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

// https://datatracker.ietf.org/doc/html/rfc4648#section-4
fn from_base64_char(c: char) -> Result<u8, InvalidBase64Char> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(c as u8 - b'a' + 26),
        '0'..='9' => Ok(c as u8 - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(InvalidBase64Char { character: c }),
    }
}

pub fn to_base64(data: &[u8]) -> String {
    let mut result = String::new();
    let mut state = 0u8;
    let mut state_size = 0u8;

    for b in data {
        match state_size {
            0 => {
                result.push(to_base64_char(b >> 2));
                state = (b & 0b11) << 4;
                state_size = 2;
            }
            2 => {
                result.push(to_base64_char(state | (b >> 4)));
                state = (b & 0b1111) << 2;
                state_size = 4;
            }
            4 => {
                result.push(to_base64_char(state | (b >> 6)));
                result.push(to_base64_char(b & 0b111111));
                state = 0;
                state_size = 0;
            }
            _ => panic!("Invalid state detected"),
        }
    }
    if state_size == 2 {
        result.push(to_base64_char(state));
        result.push_str("==");
    } else if state_size == 4 {
        result.push(to_base64_char(state));
        result.push('=');
    }
    result
}

pub fn from_base64(data: &str) -> Result<Vec<u8>, InvalidBase64Char> {
    let mut output = Vec::new();
    let mut current_char = 0u8;
    let mut state_size = 0;
    for c in data.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == '=' {
            // Flush the state if we haven't
            if state_size > 4 {
                output.push(current_char);
                state_size = 0;
            }
            continue;
        }
        let new_char = from_base64_char(c)?;
        match state_size {
            0 => {
                current_char = new_char << 2;
                state_size = 6;
            }
            6 => {
                output.push(current_char | (new_char & 0b110000) >> 4);
                current_char = (new_char & 0b1111) << 4;
                state_size = 4;
            }
            4 => {
                output.push(current_char | (new_char >> 2));
                current_char = (0b11 & new_char) << 6;
                state_size = 2;
            }
            2 => {
                output.push(current_char | new_char);
                current_char = 0;
                state_size = 0;
            }
            _ => panic!("Impossible!"),
        }
    }
    Ok(output)
}

pub fn load_base64_file(file_id: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
    let mut base64_data = String::new();
    let file_name = format!("data/{}.txt", file_id);
    File::open(file_name.clone()).and_then(|mut fd| fd.read_to_string(&mut base64_data))?;
    Ok(from_base64(&base64_data)?)
}

#[cfg(test)]
mod tests {
    use crate::base64::*;
    use std::io::ErrorKind;

    // The examples were generated from the shell:
    // ~ $ echo -en "\xfa" | base64
    // +g==
    const BASE64_VALUES: [(&[u8], &str); 12] = [
        (b"Hello, world!!", "SGVsbG8sIHdvcmxkISE="),
        (b"Hello, world!", "SGVsbG8sIHdvcmxkIQ=="),
        (b"Hello, world", "SGVsbG8sIHdvcmxk"),
        (b"foobar", "Zm9vYmFy"),
        (b"", ""),
        (&[0], "AA=="),
        (&[0, 1], "AAE="),
        (&[0, 1, 2], "AAEC"),
        (&[0, 1, 2, 0xff], "AAEC/w=="),
        (&[0x0f], "Dw=="),
        (&[0xfe], "/g=="),
        (&[0xfa], "+g=="),
    ];

    #[test]
    fn test_tobase64() {
        for (data, b64_data) in BASE64_VALUES {
            println!("data: {:?} -> base64_data: {}", data, b64_data);
            assert_eq!(to_base64(data), b64_data);
        }
    }

    #[test]
    fn test_frombase64() {
        for (data, b64_data) in BASE64_VALUES {
            println!("base64_data: {} -> data: {:?}", b64_data, data);
            assert_eq!(from_base64(b64_data).unwrap(), data);
        }

        assert_eq!(
            from_base64("SmU gcG\n Vuc2Ug\tZG9u  YyBqZSB\r\nzdWlzCg==").unwrap(),
            b"Je pense donc je suis\n"
        );
        assert!(from_base64("Je & pense").is_err());
    }

    #[test]
    fn test_load_base64_file() {
        let load_result = load_base64_file("UNKNOWN");
        assert!(load_result.is_err());
        let concrete_error = load_result.unwrap_err();
        let io_error = concrete_error.downcast::<std::io::Error>();
        assert!(io_error.is_ok());
        assert_eq!(io_error.unwrap().kind(), ErrorKind::NotFound);
    }
}
