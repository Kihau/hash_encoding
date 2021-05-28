// Source: https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/

use std::fs::File;
use std::io;
use std::io::prelude::*;

#[derive(Debug)]
enum DisplayMode {
    Binary,
    Hexadecimal,
    Character,
    Integer
}

fn main() -> io::Result<()> {

    let mut show_chunks = false;
    let mut display = DisplayMode::Hexadecimal;

    loop {
        println!("{:-<50}", "-");
        println!("Welcome to Sha256 endcoder created by Kihau!");
        println!("Current display mode is set to: {:?}", display);
        println!("{:-<50}", "-");
        println!("Available input options:");
        println!("1. \"string [message]\" - encodes a message");
        println!("2. \"file [path]\" - encodes a file");
        println!("3. \"chunks\" - prints generated chunks");
        println!("4. \"display (bin/hex/char/int)\" - changes display mode");
        println!("5. \"quit\" - exits the program");

        print!("Input: ");
        io::stdout().flush().unwrap();

        let input = get_input();
        let mut _hash = String::new();

        match input.0 {
            "string " => {
                _hash = generate_hash256(input.1.as_bytes(), show_chunks, &display);
                println!("\nGenerated hash code:\n{0}", _hash)
            }
            "file " => {
                let file = File::open(input.1);
                match file {
                    Ok(mut f) => {
                        let mut buffer = Vec::new();
                        f.read_to_end(&mut buffer)?;
                        _hash = generate_hash256(buffer.as_slice(), show_chunks, &display);
                        println!("\nGenerated hash code:\n{0}", _hash)
                    }
                    Err(_) => println!("\nGiven path is incorrect"),
                }
            }
            "chunks" => {
                show_chunks = !show_chunks;
                println!("\nChunk visibility in now set to: {}", show_chunks);
            }
            "display " => {
                let out  = input.1.as_str();
                match out {
                    "bin" => display = DisplayMode::Binary,
                    "hex" => display = DisplayMode::Hexadecimal,
                    "char" => display = DisplayMode::Character,
                    "int" => display = DisplayMode::Integer,
                    _ => {}
                }
                continue;
            }
            "quit" => break,
            &_ => println!("\nGiven input is incorrect"),
        }
    }
    Ok(())
}

fn get_input() -> (&'static str, String) {
    use std::io::{stdin, stdout};
    let mut input = String::new();

    let mut res = "";

    let _ = stdout().flush();
    stdin()
        .read_line(&mut input)
        .expect("Did not enter a correct string");

    input = String::from(input.trim());


    let outputs = vec![ "string ", "file ", "chunks", "display ", "quit" ];
    for out in outputs.iter() {
        if input.starts_with(out) {
            res = out;
            input.replace_range(0..out.len(), "");
            break;
        }
    }

    (res, String::from(input.trim()))
}

const CUBE_FRACT: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn generate_hash256(bytes: &[u8], show_chunks: bool, display: &DisplayMode) -> String {
    let mut big_endian = (bytes.len() as u64 * 8).to_be_bytes().to_vec();
    let mut bytes = bytes.to_vec();

    // Calculate number of chunks required to be pushed
    bytes.push(0b1000_0000);
    let mut chunks = bytes.len() + 8;
    while chunks > 64 {
        chunks -= 64;
    }
    chunks = 64 - chunks;

    // Push empty bytes to a chunk vector
    for _ in 0..chunks {
        bytes.push(0b0000_00000);
    }

    // Push big endian chunks
    bytes.append(&mut big_endian);

    if show_chunks {
        print_binary_vecu8(&bytes);
        println!("Generated (x * 512) bit, data chunks");
    }

    let mut sqrt_fract: Vec<u32> = vec![
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Vector of bytes gets separated into smaller 512 bit (64 byte) chunks and added to u32 vector
    let mut chunks = 0;
    while chunks < bytes.len() {
        // generating u32 chunks of data
        let mut w = Vec::<u32>::new();

        let mut size = 0;
        while size < 64 {
            let curr = chunks + size;
            let num = u32::from_be_bytes([
                bytes[curr],
                bytes[curr + 1],
                bytes[curr + 2],
                bytes[curr + 3],
            ]);
            w.push(num);
            size += 4;
        }

        // Pushing 48 empty bytes
        for _ in 0..48 {
            w.push(0)
        }

        // Computing recently appended bytes
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        if show_chunks {
            print_binary_vecu32(&w);
            println!("Generated u32 array data chunk");
        }

        // Compression
        let mut sf = sqrt_fract.clone();
        for i in 0..64 {
            let s1 = sf[4].rotate_right(6) ^ sf[4].rotate_right(11) ^ sf[4].rotate_right(25);
            let ch = (sf[4] & sf[5]) ^ ((!sf[4]) & sf[6]);
            let temp1 = sf[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(CUBE_FRACT[i])
                .wrapping_add(w[i]);
            let s0 = sf[0].rotate_right(2) ^ sf[0].rotate_right(13) ^ sf[0].rotate_right(22);
            let maj = (sf[0] & sf[1]) ^ (sf[0] & sf[2]) ^ (sf[1] & sf[2]);
            let temp2 = s0.wrapping_add(maj);
            for i in (1..8).rev() {
                if i == 4 {
                    sf[i] = sf[i - 1].wrapping_add(temp1);
                } else {
                    sf[i] = sf[i - 1];
                }
            }

            sf[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..sqrt_fract.len() {
            sqrt_fract[i] = sf[i].wrapping_add(sqrt_fract[i]);
        }

        chunks += 64;
    }

    // Compute hash
    let mut hash = String::new();

    match display {
        DisplayMode::Binary => {
            for i in sqrt_fract.iter() {
                hash.push_str(format!("{:b}", i).as_str())
            }
        }
        DisplayMode::Hexadecimal => {
            for i in sqrt_fract.iter() {
                hash.push_str(format!("{:08x}", i).as_str())
            }
            hash = hash.to_uppercase()
        }
        DisplayMode::Character => {
            hash.push_str(format!("Not implemented yet!").as_str())
        }
        DisplayMode::Integer => {
            for i in sqrt_fract.iter() {
                hash.push_str(format!("{}", i).as_str())
            }
        }
    }
    hash
}

use std::io::Write;
fn print_binary_vecu8(bytes: &Vec<u8>) {
    for i in 0..bytes.len() {
        if i % 8 == 0 {
            println!();
        }
        print!("{:08b} ", bytes[i]);
    }
    io::stdout().flush().unwrap();

    println!();
}

fn print_binary_vecu32(bytes: &Vec<u32>) {
    for i in 0..bytes.len() {
        if i % 2 == 0 {
            println!();
        }
        print!("{:032b} ", bytes[i]);
    }
    io::stdout().flush().unwrap();

    println!();
}
