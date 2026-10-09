//! Evaluates the tfjs model stored by SpamClassifierStorageFacade.ts (Dense layers only).

use minicbor::data::Type;
use minicbor::Decoder;

/// Must match `LOCAL_SPAM_CLASSIFICATION_STORAGE_VERSION` in SpamClassifierStorageFacade.ts
const STORAGE_VERSION: u64 = 1;
/// Must match `DEFAULT_PREDICTION_THRESHOLD` in SpamClassifier.ts
const DEFAULT_PREDICTION_THRESHOLD: f64 = 0.55;

#[derive(Debug, thiserror::Error)]
pub enum SpamModelError {
	#[error("invalid spam model encoding: {0}")]
	Encoding(String),
	#[error("unsupported spam model: {0}")]
	Unsupported(String),
}

impl From<minicbor::decode::Error> for SpamModelError {
	fn from(e: minicbor::decode::Error) -> Self {
		SpamModelError::Encoding(e.to_string())
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Activation {
	Linear,
	Relu,
	Sigmoid,
}

#[derive(Debug, Clone)]
struct DenseLayer {
	input_size: usize,
	output_size: usize,
	/// row-major `[input_size][output_size]`
	kernel: Vec<f32>,
	bias: Vec<f32>,
	activation: Activation,
}

#[derive(Debug, Clone)]
pub struct SpamModel {
	layers: Vec<DenseLayer>,
	pub ham_count: f64,
	pub spam_count: f64,
}

struct RawModel {
	version: Option<u64>,
	model_topology: Option<String>,
	weight_specs: Option<String>,
	weight_data: Option<Vec<u8>>,
	ham_count: Option<f64>,
	spam_count: Option<f64>,
}

fn read_number(d: &mut Decoder) -> Result<f64, SpamModelError> {
	Ok(match d.datatype()? {
		Type::U8 | Type::U16 | Type::U32 | Type::U64 => d.u64()? as f64,
		Type::I8 | Type::I16 | Type::I32 | Type::I64 => d.i64()? as f64,
		Type::F16 | Type::F32 => f64::from(d.f32()?),
		Type::F64 => d.f64()?,
		other => {
			return Err(SpamModelError::Encoding(format!(
				"expected a number, got {other}"
			)))
		},
	})
}

fn read_map_len(d: &mut Decoder) -> Result<u64, SpamModelError> {
	d.map()?
		.ok_or_else(|| SpamModelError::Encoding("indefinite length maps are not supported".into()))
}

fn decode_raw(bytes: &[u8]) -> Result<RawModel, SpamModelError> {
	let mut d = Decoder::new(bytes);
	let mut raw = RawModel {
		version: None,
		model_topology: None,
		weight_specs: None,
		weight_data: None,
		ham_count: None,
		spam_count: None,
	};
	for _ in 0..read_map_len(&mut d)? {
		let key = d.str()?.to_owned();
		match key.as_str() {
			"version" => raw.version = Some(read_number(&mut d)? as u64),
			"modelTopology" => raw.model_topology = Some(d.str()?.to_owned()),
			"weightSpecs" => raw.weight_specs = Some(d.str()?.to_owned()),
			"weightData" => raw.weight_data = Some(d.bytes()?.to_vec()),
			"metaData" => {
				for _ in 0..read_map_len(&mut d)? {
					let meta_key = d.str()?.to_owned();
					match meta_key.as_str() {
						"hamCount" => raw.ham_count = Some(read_number(&mut d)?),
						"spamCount" => raw.spam_count = Some(read_number(&mut d)?),
						_ => d.skip()?,
					}
				}
			},
			_ => d.skip()?,
		}
	}
	Ok(raw)
}

fn missing(field: &str) -> SpamModelError {
	SpamModelError::Encoding(format!("missing {field}"))
}

impl SpamModel {
	pub fn decode(bytes: &[u8]) -> Result<SpamModel, SpamModelError> {
		let raw = decode_raw(bytes)?;
		if raw.version != Some(STORAGE_VERSION) {
			return Err(SpamModelError::Unsupported(format!(
				"storage version {:?}",
				raw.version
			)));
		}
		let topology: serde_json::Value =
			serde_json::from_str(&raw.model_topology.ok_or_else(|| missing("modelTopology"))?)
				.map_err(|e| SpamModelError::Encoding(e.to_string()))?;
		let weight_specs: serde_json::Value =
			serde_json::from_str(&raw.weight_specs.ok_or_else(|| missing("weightSpecs"))?)
				.map_err(|e| SpamModelError::Encoding(e.to_string()))?;
		let weight_data = raw.weight_data.ok_or_else(|| missing("weightData"))?;

		let layer_configs = topology
			.pointer("/config/layers")
			.and_then(|l| l.as_array())
			.ok_or_else(|| SpamModelError::Unsupported("no layers in topology".into()))?;
		let specs = weight_specs
			.as_array()
			.ok_or_else(|| SpamModelError::Encoding("weightSpecs is not an array".into()))?;

		let mut weights = weight_data
			.chunks_exact(4)
			.map(|c| f32::from_le_bytes(c.try_into().unwrap()));
		let mut spec_index = 0;
		let mut layers = Vec::with_capacity(layer_configs.len());
		for layer_config in layer_configs {
			let class_name = layer_config["class_name"].as_str().unwrap_or_default();
			if class_name != "Dense" {
				return Err(SpamModelError::Unsupported(format!(
					"layer type {class_name}"
				)));
			}
			let config = &layer_config["config"];
			let activation = match config["activation"].as_str() {
				Some("relu") => Activation::Relu,
				Some("sigmoid") => Activation::Sigmoid,
				Some("linear") | None => Activation::Linear,
				Some(other) => {
					return Err(SpamModelError::Unsupported(format!("activation {other}")))
				},
			};
			let use_bias = config["use_bias"].as_bool().unwrap_or(true);

			let kernel_spec = specs
				.get(spec_index)
				.ok_or_else(|| missing("kernel weight spec"))?;
			spec_index += 1;
			check_float32(kernel_spec)?;
			let shape = kernel_spec["shape"]
				.as_array()
				.filter(|s| s.len() == 2)
				.ok_or_else(|| SpamModelError::Unsupported("kernel is not 2D".into()))?;
			let input_size = shape[0].as_u64().ok_or_else(|| missing("kernel shape"))? as usize;
			let output_size = shape[1].as_u64().ok_or_else(|| missing("kernel shape"))? as usize;
			let kernel: Vec<f32> = weights.by_ref().take(input_size * output_size).collect();
			if kernel.len() != input_size * output_size {
				return Err(SpamModelError::Encoding("weightData too short".into()));
			}

			let bias = if use_bias {
				let bias_spec = specs
					.get(spec_index)
					.ok_or_else(|| missing("bias weight spec"))?;
				spec_index += 1;
				check_float32(bias_spec)?;
				let bias: Vec<f32> = weights.by_ref().take(output_size).collect();
				if bias.len() != output_size {
					return Err(SpamModelError::Encoding("weightData too short".into()));
				}
				bias
			} else {
				vec![0.0; output_size]
			};

			if let Some(previous) = layers.last() {
				let previous: &DenseLayer = previous;
				if previous.output_size != input_size {
					return Err(SpamModelError::Unsupported(
						"layer sizes do not chain".into(),
					));
				}
			}
			layers.push(DenseLayer {
				input_size,
				output_size,
				kernel,
				bias,
				activation,
			});
		}
		if layers.is_empty() || layers.last().unwrap().output_size != 1 {
			return Err(SpamModelError::Unsupported(
				"expected a single output".into(),
			));
		}

		Ok(SpamModel {
			layers,
			ham_count: raw.ham_count.ok_or_else(|| missing("hamCount"))?,
			spam_count: raw.spam_count.ok_or_else(|| missing("spamCount"))?,
		})
	}

	pub fn input_size(&self) -> usize {
		self.layers[0].input_size
	}

	pub fn predict_probability(&self, input: &[f32]) -> Result<f32, SpamModelError> {
		if input.len() != self.input_size() {
			return Err(SpamModelError::Unsupported(format!(
				"model expects {} inputs, got {}",
				self.input_size(),
				input.len()
			)));
		}
		let mut activations = input.to_vec();
		for layer in &self.layers {
			let mut next = layer.bias.clone();
			for (i, &x) in activations.iter().enumerate() {
				if x == 0.0 {
					continue;
				}
				let row = &layer.kernel[i * layer.output_size..(i + 1) * layer.output_size];
				for (n, w) in next.iter_mut().zip(row) {
					*n += x * w;
				}
			}
			for n in &mut next {
				*n = match layer.activation {
					Activation::Linear => *n,
					Activation::Relu => n.max(0.0),
					Activation::Sigmoid => 1.0 / (1.0 + (-*n).exp()),
				};
			}
			activations = next;
		}
		Ok(activations[0])
	}

	/// `SpamClassifier.calculateThreshold`
	pub fn threshold(&self) -> f64 {
		let ham_to_spam_ratio = self.ham_count / self.spam_count;
		let mut threshold = -0.1 * (ham_to_spam_ratio * 10.0).log10() + 0.65;
		if threshold < DEFAULT_PREDICTION_THRESHOLD {
			threshold = DEFAULT_PREDICTION_THRESHOLD;
		} else if threshold > 0.75 {
			threshold = 0.75;
		}
		threshold
	}

	/// `SpamClassifier.predict`: `prediction > threshold`
	pub fn is_spam(&self, input: &[f32]) -> Result<(bool, f32), SpamModelError> {
		let probability = self.predict_probability(input)?;
		Ok((f64::from(probability) > self.threshold(), probability))
	}
}

fn check_float32(spec: &serde_json::Value) -> Result<(), SpamModelError> {
	match spec["dtype"].as_str() {
		Some("float32") | None => Ok(()),
		Some(other) => Err(SpamModelError::Unsupported(format!("weight dtype {other}"))),
	}
}
