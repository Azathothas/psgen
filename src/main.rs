//! psgen: realistic Linux process lists on stdout, or in the real process
//! table.

mod activity;
mod check;
mod cli;
mod corpus;
mod doctor;
mod gen;
mod inject;
mod live;
mod loggen;
mod probe;
mod rng;
mod str;
mod stub;
mod sys;
mod table;
mod unit;
mod users;
mod util;
mod version;

fn main() {
    sys::ignore_sigxfsz();
    stub::maybe_run();
    let code = cli::run();
    sys::exit(code);
}
