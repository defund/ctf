#![allow(warnings)]

use std::marker::PhantomData;

use fancy_garbling::{
    // check_binary,
    errors::{EvaluatorError, FancyError},
    hash_wires,
    util::{self, output_tweak, tweak, tweak2},
    AllWire,
    ArithmeticWire,
    Fancy,
    FancyArithmetic,
    FancyBinary,
    FancyReveal,
    HasModulus,
    WireLabel,
    WireMod2,
};
use itertools::Itertools;
use num_integer::Integer;
use scuttlebutt::{AbstractChannel, Block};
use std::collections::{HashMap, HashSet};
use subtle::ConditionallySelectable;

pub struct Leak<Wire> {
    pub projs: Vec<(Wire, u16, Vec<Block>, Block)>,
    pub deltas: HashMap<u16, Wire>,
    pub has_deltas: bool,
    pub hooks: HashMap<Block, Block>,
    pub has_hooks: bool,
    pub delta_guesses: Option<HashSet<Block>>,
    pub expected: HashMap<u16, Vec<u16>>,
    pub bias_residues: Vec<Vec<u16>>,
}

impl<Wire: WireLabel> Leak<Wire> {
    fn new() -> Self {
        let mut expected = HashMap::new();
        expected.insert(2, get_diffs(vec![0, 43], 86));
        expected.insert(3, get_diffs(vec![0, 28, 57], 86));
        expected.insert(5, get_diffs(vec![0, 51, 17, 68, 34], 86));
        expected.insert(7, get_diffs(vec![0, 24, 49, 73, 12, 36, 61], 86));
        expected.insert(
            11,
            get_diffs(vec![0, 7, 15, 23, 31, 39, 46, 54, 62, 70, 78], 86),
        );
        expected.insert(
            13,
            get_diffs(vec![0, 26, 52, 79, 19, 46, 72, 13, 39, 66, 6, 33, 59], 86),
        );
        expected.insert(
            17,
            get_diffs(
                vec![
                    0, 75, 65, 55, 45, 35, 25, 15, 5, 80, 70, 60, 50, 40, 30, 20, 10,
                ],
                86,
            ),
        );

        Leak {
            projs: Vec::new(),
            deltas: HashMap::new(),
            has_deltas: false,
            hooks: HashMap::new(),
            has_hooks: false,
            delta_guesses: None,
            expected,
            bias_residues: vec![Vec::new(); 7],
        }
    }
}

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<C, Wire> {
    channel: C,
    current_gate: usize,
    current_output: usize,
    _phantom: PhantomData<Wire>,
    pub leak: Leak<Wire>,
}

impl<C: AbstractChannel, Wire: WireLabel> Evaluator<C, Wire> {
    /// Create a new `Evaluator`.
    pub fn new(channel: C) -> Self {
        Evaluator {
            channel,
            current_gate: 0,
            current_output: 0,
            _phantom: PhantomData,
            leak: Leak::new(),
        }
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self, modulus: u16) -> Result<Wire, EvaluatorError> {
        let block = self.channel.read_block()?;
        Ok(Wire::from_block(block, modulus))
    }

    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    fn evaluate_and_gate(
        &mut self,
        A: &WireMod2,
        B: &WireMod2,
        gate0: &Block,
        gate1: &Block,
    ) -> WireMod2 {
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = WireMod2::from_block(
            Block::conditional_select(&hashA, &(hashA ^ *gate0), (A.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let R = WireMod2::from_block(
            Block::conditional_select(&hashB, &(hashB ^ *gate1), (B.color() as u8).into()),
            2,
        );

        L.plus_mov(&R.plus_mov(&A.cmul(B.color())))
    }
}

impl<C: AbstractChannel> FancyBinary for Evaluator<C, WireMod2> {
    /// Negate is a noop for the evaluator
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(*x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    fn and(&mut self, A: &Self::Item, B: &Self::Item) -> Result<Self::Item, Self::Error> {
        let gate0 = self.channel.read_block()?;
        let gate1 = self.channel.read_block()?;
        Ok(self.evaluate_and_gate(A, B, &gate0, &gate1))
    }
}

impl<C: AbstractChannel, Wire: WireLabel> FancyReveal for Evaluator<C, Wire> {
    fn reveal(&mut self, x: &Wire) -> Result<u16, EvaluatorError> {
        let val = self.output(x)?.expect("Evaluator always outputs Some(u16)");
        self.channel.write_u16(val)?;
        self.channel.flush()?;
        Ok(val)
    }
}

impl<C: AbstractChannel> FancyBinary for Evaluator<C, AllWire> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        // check_binary!(x);

        Ok(x.clone())
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        // check_binary!(x);
        // check_binary!(y);

        self.add(x, y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if let (AllWire::Mod2(ref A), AllWire::Mod2(ref B)) = (x, y) {
            let gate0 = self.channel.read_block()?;
            let gate1 = self.channel.read_block()?;
            return Ok(AllWire::Mod2(self.evaluate_and_gate(A, B, &gate0, &gate1)));
        }

        // If we got here, one of the wires isn't binary
        // check_binary!(x);
        // check_binary!(y);

        // Shouldn't be reachable, unless the wire has modulus 2 but is not AllWire::Mod2()
        unreachable!()
    }
}

impl<C: AbstractChannel, Wire: WireLabel + ArithmeticWire> FancyArithmetic for Evaluator<C, Wire> {
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = self.channel.read_block()?;
                gate.push(block);
            }
        }
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = if A.color() == 0 {
            Wire::hash_to_mod(hashA, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ hashA, q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            Wire::hash_to_mod(hashB, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ hashB, q)
        };

        // hack for unequal mods
        // TODO: Batch this with original hash if unequal.
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }

    fn proj(&mut self, x: &Wire, q: u16, _: Option<Vec<u16>>) -> Result<Wire, EvaluatorError> {
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = self.channel.read_block()?;
            gate.push(block);
        }
        let t = tweak(self.current_gate());
        let wire = if x.color() == 0 {
            x.hashback(t, q)
        } else {
            let ct = gate[x.color() as usize - 1];
            Wire::from_block(ct ^ x.hash(t), q)
        };

        self.leak.projs.push((x.clone(), q, gate.clone(), t));

        if x.modulus() != q && !self.leak.deltas.contains_key(&q) {
            if x.modulus() == 86 && q == 2 {
                let delta_guesses: HashSet<Block> = (0..util::digits_per_u128(86))
                    .map(|i| if i == 0 { 1..2 } else { 0..2 })
                    .multi_cartesian_product()
                    .map(|guess| {
                        let x_delta = Wire::from_block(
                            Block::from(util::from_base_q(&guess, x.modulus())),
                            x.modulus(),
                        )
                        .cmul_mov(43);
                        let new_wire = decrypt(&x.plus(&x_delta), q, &gate, t);
                        wire.minus(&new_wire)
                    })
                    .filter(|w| w.color() != 0)
                    .map(|w| w.as_block())
                    .collect();

                if let Some(other) = &self.leak.delta_guesses {
                    let mut collisions = delta_guesses.intersection(other);
                    let delta = Wire::from_block(*collisions.next().unwrap(), q);
                    assert!(collisions.next().is_none());
                    println!("ev: found delta for {:?}: {:?}", q, delta.as_block());
                    self.leak.deltas.insert(q, delta);
                } else {
                    self.leak.delta_guesses = Some(delta_guesses);
                }
            } else if let Some(x_delta) = self.leak.deltas.get(&x.modulus()) {
                let x_delta = x_delta.clone();
                for delta in (1..x.modulus())
                    .map(|c| {
                        let new_wire = decrypt(&x.plus(&x_delta.cmul(c)), q, &gate, t);
                        wire.minus(&new_wire)
                    })
                    .filter(|w| w.color() != 0)
                    .filter_map(|w| {
                        let egcd = (w.color() as i64).extended_gcd(&(q as i64));
                        match egcd.gcd {
                            1 => Some(w.cmul_mov(egcd.x.rem_euclid(q as i64) as u16)),
                            _ => None,
                        }
                    })
                {
                    assert_eq!(delta.color(), 1);
                    println!("ev: found delta for {:?}: {:?}", q, delta.as_block());
                    self.leak.deltas.insert(q, delta);
                    break;
                }
            }
        }

        if self.leak.has_deltas {
            // mixed radix conversion
            if x.modulus() != 2
                && q == 86
                && self.leak.projs.len() >= 5
                && self.leak.projs[self.leak.projs.len() - 5..]
                    .iter()
                    .all(|(z, _, _, _)| z.modulus() == x.modulus())
            {
                let delta = self.leak.deltas.get(&x.modulus()).unwrap();
                let colors = get_colors(delta, &x, q, &gate, t);
                let diffs = get_diffs(colors, q);
                let expected = self.leak.expected.get(&x.modulus()).unwrap();
                let shift = find_shift(expected, &diffs).unwrap();
                let val = (x.color() + x.modulus() - shift) % x.modulus();

                if self.leak.has_hooks {
                    self.leak.bias_residues[prime_index(x.modulus())].push(val);
                } else {
                    let y = x.minus(&delta.cmul(val + 1));
                    self.leak.hooks.insert(x.as_block(), y.as_block());
                }
            }

            // sign output
            if x.modulus() == 2 && q == 17 {
                let delta = self.leak.deltas.get(&x.modulus()).unwrap();
                let colors = get_colors(delta, &x, q, &gate, t);
                let diffs = get_diffs(colors, q);
                let expected = get_diffs(vec![1, q - 1], q);
                let shift = find_shift(&expected, &diffs).unwrap();
                let val = (x.color() + x.modulus() - shift) % x.modulus();
                self.leak.bias_residues[prime_index(2)].push(val);
            }
        }

        if let Some(block) = self.leak.hooks.get(&x.as_block()) {
            let x = Wire::from_block(*block, x.modulus());
            return Ok(decrypt(&x, q, &gate, t));
        }

        Ok(wire)
    }
}

impl<C: AbstractChannel, Wire: WireLabel> Fancy for Evaluator<C, Wire> {
    type Item = Wire;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.read_wire(q)
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, EvaluatorError> {
        let q = x.modulus();
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let ct = self.channel.read_blocks(q as usize)?;

        // Attempt to brute force x using the output ciphertext
        let mut decoded = None;
        for k in 0..q {
            let hashed_wire = x.hash(output_tweak(i, k));
            if hashed_wire == ct[k as usize] {
                decoded = Some(k);
                break;
            }
        }

        if let Some(output) = decoded {
            Ok(Some(output))
        } else {
            Err(EvaluatorError::DecodingFailed)
        }
    }
}

pub fn decrypt<Wire: WireLabel>(x: &Wire, q: u16, gate: &[Block], t: Block) -> Wire {
    if x.color() == 0 {
        x.hashback(t, q)
    } else {
        let ct = gate[x.color() as usize - 1];
        Wire::from_block(ct ^ x.hash(t), q)
    }
}

fn get_colors<Wire: WireLabel>(
    delta: &Wire,
    x: &Wire,
    q: u16,
    gate: &[Block],
    t: Block,
) -> Vec<u16> {
    let mut y = delta.cmul(x.color()).negate_mov().plus_mov(x);
    let mut colors = Vec::with_capacity(x.modulus().into());
    for i in 0..x.modulus() {
        assert_eq!(y.color(), i);
        let new_wire = if y.color() == 0 {
            y.hashback(t, q)
        } else {
            let ct = gate[y.color() as usize - 1];
            Wire::from_block(ct ^ y.hash(t), q)
        };
        y.plus_eq(delta);
        colors.push(new_wire.color());
    }
    colors
}

pub fn get_diffs(a: Vec<u16>, q: u16) -> Vec<u16> {
    let mut b = Vec::with_capacity(a.len());
    b.push((a[0] + q - a[a.len() - 1]) % q);
    for i in 0..a.len() - 1 {
        b.push((a[i + 1] + q - a[i]) % q);
    }
    b
}

fn find_shift(a: &[u16], b: &[u16]) -> Option<u16> {
    assert_eq!(a.len(), b.len());
    let mut c = Vec::with_capacity(2 * b.len());
    c.extend_from_slice(b);
    c.extend_from_slice(b);
    for i in 0..b.len() {
        if a == &c[i..i + b.len()] {
            return Some(i as u16);
        }
    }
    None
}

fn prime_index(q: u16) -> usize {
    util::PRIMES.iter().position(|&p| p == q).unwrap()
}
