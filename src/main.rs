extern crate env_logger;

mod aes;
mod base64;
mod block;
mod decrypt;
mod encrypt;
mod hex;
mod set1;
mod set2;

fn main() {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    set1::run();

    set2::run();
}
