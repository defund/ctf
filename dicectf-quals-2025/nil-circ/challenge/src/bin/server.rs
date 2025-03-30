use std::fs::File;
use std::io;
use std::net::TcpListener;

use clap::Parser;
use fancy_garbling::{
    FancyInput, WireMod2,
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
    twopac::semihonest::Garbler,
};
use scuttlebutt::{AbstractChannel, AesRng, Channel, SymChannel};

use nil_circ::{
    BLOCK_SIZE, unpack_block,
    ot::Sender,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    address: Option<String>,

    #[arg(long)]
    circuit: String,

    #[arg(long)]
    key: String,
}

fn handle<C: AbstractChannel>(mut channel: C, circ: &Circuit, key: &[u8]) -> io::Result<()> {
    static WIRE_SPEC: [u16; 128] = [2; BLOCK_SIZE * 8];

    channel.write_bytes(b"NILCIRC\n")?;

    let rng = AesRng::new();
    let mut gb = Garbler::<_, _, Sender, WireMod2>::new(channel, rng).unwrap();
    let inp_wires = gb.receive_many(&WIRE_SPEC).unwrap();
    let key_wires = gb.encode_many(&unpack_block(key), &WIRE_SPEC).unwrap();
    circ.eval(&mut gb, &inp_wires, &key_wires).unwrap();

    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let file = File::open(args.circuit)?;
    let reader = io::BufReader::new(file);
    let circ = Circuit::parse(reader).expect("invalid circuit file");

    let key = &hex::decode(args.key).expect("key must be hex");
    assert!(key.len() == 16, "key must be 16 bytes");

    if let Some(address) = args.address {
        let listener = TcpListener::bind(address)?;
        for stream in listener.incoming() {
            let channel = SymChannel::new(stream?);
            handle(channel, &circ, key)?;
        }
    } else {
        let channel = Channel::new(io::stdin(), io::stdout());
        handle(channel, &circ, key)?;
    }

    Ok(())
}
