use std::fs::File;
use std::io;
use std::net::TcpStream;

use clap::Parser;
use fancy_garbling::{
    FancyInput, WireMod2,
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
    twopac::semihonest::Evaluator,
};
use scuttlebutt::{AbstractChannel, AesRng, SymChannel};

use nil_circ::{
    BLOCK_SIZE, pack_block, unpack_block,
    ot::Receiver,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    address: String,

    #[arg(long)]
    circuit: String,

    #[arg(long)]
    input: String,
}

fn handle<C: AbstractChannel>(mut channel: C, circ: &Circuit, inp: &[u8]) -> io::Result<()> {
    static WIRE_SPEC: [u16; 128] = [2; BLOCK_SIZE * 8];

    let mut magic = [0; 8];
    channel.read_bytes(&mut magic).unwrap();
    assert_eq!(b"NILCIRC\n", &magic);

    println!("{:?}", unpack_block(inp));

    let rng = AesRng::new();
    let mut ev = Evaluator::<_, _, Receiver, WireMod2>::new(channel, rng).unwrap();
    let inp_wires = ev.encode_many(&unpack_block(inp), &WIRE_SPEC).unwrap();
    let key_wires = ev.receive_many(&WIRE_SPEC).unwrap();
    let out = pack_block(&circ.eval(&mut ev, &inp_wires, &key_wires).unwrap().unwrap());
    println!("encrypted input: {}", hex::encode(out));

    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let file = File::open(args.circuit)?;
    let reader = io::BufReader::new(file);
    let circ = Circuit::parse(reader).expect("invalid circuit file");

    let inp = &hex::decode(args.input).expect("input must be hex");
    assert!(inp.len() == 16, "input must be 16 bytes");

    let stream = TcpStream::connect(args.address)?;
    let channel = SymChannel::new(stream);
    handle(channel, &circ, inp)?;

    Ok(())
}
