mod garble_evaluator;
mod twopac_evaluator;

use clap::Parser;
use itertools::Itertools;
use pbr::Pipe;
use rand_core::SeedableRng;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::net::TcpStream;

use fancy_garbling::twopac::semihonest::Evaluator;
use fancy_garbling::util as numbers;
use fancy_garbling::{AllWire, CrtGadgets, Fancy, FancyInput, HasModulus, WireLabel};
use ocelot::ot::AlszReceiver;
use scuttlebutt::AesRng;
use scuttlebutt::Block;
use scuttlebutt::{AbstractChannel, Channel, SymChannel};

use dicenet::layer::Accuracy;
use dicenet::neural_net::NeuralNet;
use dicenet::util;

use garble_evaluator::{decrypt, get_diffs, Leak};
use twopac_evaluator::Evaluator as CustomEvaluator;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    address: Option<String>,

    #[arg(long)]
    model: String,

    // use the dummy weights file
    #[arg(long)]
    weights: String,
}

struct RecordChannel<C1: AbstractChannel, C2: AbstractChannel>(C1, C2);

impl<C1: AbstractChannel, C2: AbstractChannel> RecordChannel<C1, C2> {
    fn new(channel: C1, dump: C2) -> Self {
        RecordChannel(channel, dump)
    }
}

impl<C1: AbstractChannel, C2: AbstractChannel> AbstractChannel for RecordChannel<C1, C2> {
    // add code here
    fn read_bytes(&mut self, bytes: &mut [u8]) -> Result<(), std::io::Error> {
        self.0.read_bytes(bytes)?;
        self.1.write_bytes(bytes)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.0.write_bytes(bytes)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.0.flush()
    }

    fn clone(&self) -> Self {
        RecordChannel(self.0.clone(), self.1.clone())
    }
}

fn run_custom_evaluator<C: AbstractChannel>(
    mut channel: C,
    nn: &NeuralNet,
    moduli: &[u128],
    accuracy: &Accuracy,
    deltas: Option<&HashMap<u16, AllWire>>,
    hooks: Option<&HashMap<Block, Block>>,
) -> Leak<AllWire> {
    let mut magic = [0; 8];
    channel.read_bytes(&mut magic).unwrap();
    assert_eq!(b"DICENET\n", &magic);
    let rng = AesRng::from_seed(Block::default());
    let mut ev = CustomEvaluator::<_, _, AlszReceiver, AllWire>::new(channel, rng).unwrap();

    if let Some(deltas) = deltas {
        ev.evaluator.leak.deltas = deltas.clone();
        ev.evaluator.leak.has_deltas = true;
    }
    if let Some(hooks) = hooks {
        ev.evaluator.leak.hooks = hooks.clone();
        ev.evaluator.leak.has_hooks = true;
    }

    let inputs = ev
        .crt_encode_many(&vec![0; nn.num_inputs()], moduli[0])
        .unwrap();
    let scores =
        nn.eval_arith::<_, _, Pipe>(&mut ev, &inputs, &moduli, None, 0, true, false, &accuracy);
    let bit = ev.crt_geq(&scores[0], &scores[1], &accuracy.sign).unwrap();
    ev.output(&bit).unwrap();
    ev.evaluator.leak
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let nn = NeuralNet::from_json(&args.model, &args.weights);
    let accuracy = Accuracy {
        relu: "100%".to_string(),
        sign: "100%".to_string(),
        max: "100%".to_string(),
    };
    let bitwidths = vec![15; nn.nlayers() + 1];
    let moduli = bitwidths
        .iter()
        .map(|&b| numbers::modulus_with_width(b as u32))
        .collect_vec();

    if let Some(address) = args.address {
        println!("dumping from server...");
        let stream = TcpStream::connect(address)?;
        let dump = File::create("dump")?;
        let mut channel = RecordChannel::new(SymChannel::new(stream), SymChannel::new(dump));
        let mut magic = [0; 8];
        channel.read_bytes(&mut magic).unwrap();
        assert_eq!(b"DICENET\n", &magic);
        let rng = AesRng::from_seed(Block::default());
        let mut ev = Evaluator::<_, _, AlszReceiver, AllWire>::new(channel, rng).unwrap();
        let inputs = ev
            .crt_encode_many(&vec![0; nn.num_inputs()], moduli[0])
            .unwrap();
        let scores =
            nn.eval_arith::<_, _, Pipe>(&mut ev, &inputs, &moduli, None, 0, true, false, &accuracy);
        let bit = ev.crt_geq(&scores[0], &scores[1], &accuracy.sign).unwrap();
        ev.output(&bit).unwrap();
        println!("done");
    }

    println!("leaking deltas...");
    let dump = File::open("dump")?;
    let channel = Channel::new(dump, io::sink());
    let deltas = run_custom_evaluator(channel, &nn, &moduli, &accuracy, None, None).deltas;
    println!("done");

    println!("getting hooks...");
    let dump = File::open("dump")?;
    let channel = Channel::new(dump, io::sink());
    let hooks = run_custom_evaluator(channel, &nn, &moduli, &accuracy, Some(&deltas), None).hooks;
    println!("done");

    println!("leaking weights and biases...");
    let dump = File::open("dump")?;
    let channel = Channel::new(dump, io::sink());
    let leak = run_custom_evaluator(
        channel,
        &nn,
        &moduli,
        &accuracy,
        Some(&deltas),
        Some(&hooks),
    );
    println!("done");

    let mut biases = Vec::new();
    for i in 0..leak.bias_residues[0].len() {
        let residues = (0..7).map(|j| leak.bias_residues[j][i]).collect_vec();
        biases.push(util::from_mod_q_crt(&residues, moduli[0]));
    }
    println!("leaked {:?} biases: {:?}", biases.len(), &biases[..10]);
    fs::write("biases.txt", format!("{:?}", biases))?;

    let muls = leak
        .projs
        .iter()
        .filter(|(x, q, _, _)| numbers::PRIMES.contains(&x.modulus()) && *q == x.modulus())
        .map(|(x, q, gate, t)| decode_proj(deltas.get(&x.modulus()).unwrap(), &x, *q, gate, *t))
        .map(|diffs| {
            assert!(diffs.iter().all(|&x| x == diffs[0]));
            (diffs[0], diffs.len())
        })
        .collect_vec();

    let mut weights = Vec::new();
    for i in 0..muls.len() {
        if muls[i].1 == 17 {
            let residues: Vec<u16> = muls[i - 6..i + 1].iter().map(|(x, _)| *x).collect();
            let weight = util::from_mod_q_crt(&residues, moduli[0]);
            weights.push(weight);
        }
    }
    println!("leaked {:?} weights: {:?}", weights.len(), &weights[..10]);
    fs::write("weights.txt", format!("{:?}", weights))?;

    Ok(())
}

fn decode_proj(delta: &AllWire, x: &AllWire, q: u16, gate: &[Block], t: Block) -> Vec<u16> {
    let mut x = x.minus(&delta.cmul(x.color()));
    let mut colors = Vec::new();
    for i in 0..x.modulus() {
        assert_eq!(x.color(), i);
        let wire = decrypt(&x, q, gate, t);
        colors.push(wire.color());
        x.plus_eq(delta);
    }
    get_diffs(colors, q)
}
