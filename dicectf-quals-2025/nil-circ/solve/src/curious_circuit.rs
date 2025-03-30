#![allow(dead_code)]

use fancy_garbling::{errors::TwopacError, Fancy, FancyBinary, FancyError, WireMod2};
use rand::{CryptoRng, Rng};
use scuttlebutt::AbstractChannel;
use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufWriter, Write};

use crate::ot::Receiver;
use crate::twopac_evaluator::Evaluator;

pub type CircuitRef = usize;

pub enum BinaryGate {
    /// Input of garbler
    GarblerInput {
        /// Gate number
        id: usize,
    },
    /// Input of evaluator
    EvaluatorInput {
        /// Gate number
        id: usize,
    },
    /// Constant value
    Constant {
        /// Value of constant
        val: u16,
    },

    /// Xor gate
    Xor {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
    /// And gate
    And {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Gate number
        id: usize,

        /// Output wire index
        out: Option<usize>,
    },
    /// Not gate
    Inv {
        /// Reference to input
        xref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
}

pub struct BinaryCircuit {
    pub(crate) gates: Vec<BinaryGate>,
    pub(crate) garbler_input_refs: Vec<CircuitRef>,
    pub(crate) evaluator_input_refs: Vec<CircuitRef>,
    pub(crate) const_refs: Vec<CircuitRef>,
    pub(crate) output_refs: Vec<CircuitRef>,
    pub(crate) num_nonfree_gates: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct Constraint {
    pub(crate) bit: bool,
    pub(crate) ids: BTreeSet<usize>,
}

impl Constraint {
    fn new_id(id: usize) -> Self {
        Self {
            bit: false,
            ids: Some(id).into_iter().collect(),
        }
    }

    fn new_bit(bit: bool) -> Self {
        Self {
            bit,
            ids: BTreeSet::new(),
        }
    }

    fn xor(&self, other: &Self) -> Self {
        Self {
            bit: self.bit ^ other.bit,
            ids: self.ids.symmetric_difference(&other.ids).into_iter().cloned().collect(),
        }
    }

    fn xor_bit(&self, bit: bool) -> Self {
        Self {
            bit: self.bit ^ bit,
            ids: self.ids.clone(),
        }
    }

    fn flip_bit(&self) -> Self {
        self.xor_bit(true)
    }
}

fn add_constraint(cons: &mut Vec<Constraint>, con: &Constraint, bit: bool) {
    if con.ids.is_empty() {
        assert_eq!(con.bit, bit);
    } else {
        cons.push(con.xor_bit(bit));
    }
}

impl BinaryCircuit {
    pub fn new(ngates: Option<usize>) -> Self {
        let gates = Vec::with_capacity(ngates.unwrap_or(0));
        Self {
            gates,
            garbler_input_refs: Vec::new(),
            evaluator_input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

    /// Return the number of evaluator inputs.
    #[inline]
    fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_refs.len()
    }

    /// Return the number of outputs.
    #[inline]
    fn noutputs(&self) -> usize {
        self.output_refs.len()
    }
}

impl BinaryCircuit {
    pub fn eval<
        C: AbstractChannel,
        RNG: CryptoRng + Rng,
    >(
        &self,
        f: &mut Evaluator<C, RNG, Receiver, WireMod2>,
        garbler_inputs: &[WireMod2],
        evaluator_inputs: &[WireMod2],
    ) -> Result<Option<Vec<u16>>, TwopacError> {
        let mut tracker: BTreeMap<CircuitRef, Constraint> = BTreeMap::new();
        let mut constraints: Vec<Constraint> = Vec::new();

        let mut cache: Vec<Option<WireMod2>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let q = 2;
            let (zref_, val) = match *gate {
                BinaryGate::GarblerInput { id } => {
                    assert!(tracker.insert(i, Constraint::new_id(i)).is_none());
                    (None, garbler_inputs[id].clone())
                },
                BinaryGate::EvaluatorInput { id } => {
                    assert!(
                        id < evaluator_inputs.len(),
                        "id={} ev_inps.len()={}",
                        id,
                        evaluator_inputs.len()
                    );
                    assert!(tracker.insert(i, Constraint::new_id(i)).is_none());
                    (None, evaluator_inputs[id].clone())
                }
                BinaryGate::Constant { val } => (None, f.constant(val, q)?),
                BinaryGate::Inv { xref, out } => {
                    if let Some(xcon) = tracker.get(&xref) {
                        assert!(tracker.insert(out.unwrap_or(i), xcon.flip_bit()).is_none());
                    }
                    (
                        out,
                        f.negate(
                            cache[xref]
                                .as_ref()
                                .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?,
                        )?,
                    )
                },
                BinaryGate::Xor { xref, yref, out } => {
                    if let (Some(xcon), Some(ycon)) = (tracker.get(&xref), tracker.get(&yref)) {
                        assert!(tracker.insert(out.unwrap_or(i), xcon.xor(ycon)).is_none());
                    }
                    (
                        out,
                        f.xor(
                            cache[xref]
                                .as_ref()
                                .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?,
                            cache[yref]
                                .as_ref()
                                .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?,
                        )?,
                    )
                },
                BinaryGate::And {
                    xref, yref, out, ..
                } => {
                    let (zval, leak) = f.and_curious(
                        cache[xref]
                            .as_ref()
                            .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?,
                        cache[yref]
                            .as_ref()
                            .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?,
                    )?;
                    if let Some((xbit, ybit)) = leak {
                        if let Some(xcon) = tracker.get(&xref) {
                            add_constraint(&mut constraints, xcon, xbit);
                        }
                        if let Some(ycon) = tracker.get(&yref) {
                            add_constraint(&mut constraints, ycon, ybit);
                        }
                        assert!(tracker.insert(out.unwrap_or(i), Constraint::new_bit(xbit && ybit)).is_none());
                    }
                    (out, zval)
                },
            };
            cache[zref_.unwrap_or(i)] = Some(val);
        }

        println!("{:?} constraints", constraints.len());
        let file = File::create("constraints.json").expect("failed to create file");
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &constraints).expect("failed to write to file");
        writer.flush().expect("failed to flush file");

        let mut outputs = Vec::with_capacity(self.noutputs());
        for r in self.output_refs.iter() {
            let r = cache[*r]
                .as_ref()
                .ok_or_else(|| TwopacError::from(FancyError::UninitializedValue))?;
            let out = f.output(r)?;
            outputs.push(out);
        }
        Ok(outputs.into_iter().collect())
    }
}

