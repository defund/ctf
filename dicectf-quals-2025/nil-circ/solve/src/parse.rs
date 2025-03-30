//! Functions for parsing and running a circuit file based on the format given
//! here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>.

use fancy_garbling::{
    errors::CircuitParserError as Error,
};
use regex::{Captures, Regex};
use std::str::FromStr;

use crate::curious_circuit::{BinaryGate, BinaryCircuit};

enum GateType {
    AndGate,
    XorGate,
}

fn cap2int(cap: &Captures, idx: usize) -> Result<usize, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    FromStr::from_str(s.as_str()).map_err(Error::from)
}

fn cap2typ(cap: &Captures, idx: usize) -> Result<GateType, Error> {
    let s = cap.get(idx).ok_or(Error::ParseIntError)?;
    let s = s.as_str();
    match s {
        "AND" => Ok(GateType::AndGate),
        "XOR" => Ok(GateType::XorGate),
        s => Err(Error::ParseGateError(s.to_string())),
    }
}

fn regex2captures<'t>(re: &Regex, line: &'t str) -> Result<Captures<'t>, Error> {
    re.captures(line)
        .ok_or_else(|| Error::ParseLineError(line.to_string()))
}

impl BinaryCircuit {
    /// Generates a new `Circuit` from file `filename`. The file must follow the
    /// format given here: <https://homes.esat.kuleuven.be/~nsmart/MPC/old-circuits.html>,
    /// (Bristol Format---the OLD format---not Bristol Fashion---the NEW format) otherwise
    /// a `CircuitParserError` is returned.
    pub fn parse(mut reader: impl std::io::BufRead) -> Result<Self, Error> {
        // Parse first line: ngates nwires\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let ngates = cap2int(&cap, 1)?;
        let nwires = cap2int(&cap, 2)?;

        // Parse second line: n1 n2 n3\n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s+(\d+)\s+(\d+)")?;
        let cap = regex2captures(&re, &line)?;
        let n1 = cap2int(&cap, 1)?; // Number of garbler inputs
        let n2 = cap2int(&cap, 2)?; // Number of evaluator inputs
        let n3 = cap2int(&cap, 3)?; // Number of outputs

        // Parse third line: \n
        let mut line = String::new();
        reader.read_line(&mut line)?;
        #[allow(clippy::trivial_regex)]
        let re = Regex::new(r"\n")?;
        let _ = regex2captures(&re, &line)?;

        let mut circ = Self::new(Some(ngates));

        let re1 = Regex::new(r"1 1 (\d+) (\d+) INV")?;
        let re2 = Regex::new(r"2 1 (\d+) (\d+) (\d+) ((AND|XOR))")?;

        let mut id = 0;

        // Process garbler inputs.
        for i in 0..n1 {
            circ.gates.push(BinaryGate::GarblerInput { id: i });
            circ.garbler_input_refs.push(i);
        }
        // Process evaluator inputs.
        for i in 0..n2 {
            circ.gates.push(BinaryGate::EvaluatorInput { id: i });
            circ.evaluator_input_refs.push(n1 + i);
        }
        // Create a constant wire for negations.
        // This is no longer required for the implementation
        // of our garbler/evaluator pair. Consider removing
        circ.gates.push(BinaryGate::Constant { val: 1 });
        let oneref = n1 + n2;
        circ.const_refs.push(oneref);
        // Process outputs.
        for i in 0..n3 {
            circ.output_refs.push(nwires - n3 + i);
        }
        for line in reader.lines() {
            let line = line?;
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, &line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
                    circ.gates.push(BinaryGate::Inv {
                        xref: yref,
                        out: Some(out),
                    })
                }
                Some('2') => {
                    let cap = regex2captures(&re2, &line)?;
                    let xref = cap2int(&cap, 1)?;
                    let yref = cap2int(&cap, 2)?;
                    let out = cap2int(&cap, 3)?;
                    let typ = cap2typ(&cap, 4)?;
                    let gate = match typ {
                        GateType::AndGate => {
                            let gate = BinaryGate::And {
                                xref,
                                yref,
                                id,
                                out: Some(out),
                            };
                            id += 1;
                            gate
                        }
                        GateType::XorGate => BinaryGate::Xor {
                            xref,
                            yref,
                            out: Some(out),
                        },
                    };
                    circ.gates.push(gate);
                }
                None => break,
                _ => {
                    return Err(Error::ParseLineError(line.to_string()));
                }
            }
        }
        Ok(circ)
    }
}
