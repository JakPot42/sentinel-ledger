//! Converting a ROS geometry_msgs/Twist to the integer command the recorder takes, and
//! back. docs/SPEC.md section 15.
//!
//! A Twist holds six floating-point numbers. The specification allows integers only, so
//! the conversion happens once, at the edge, and the record holds the result: linear
//! speeds in whole millimetres per second, angular speeds in whole milliradians per
//! second, each rounded to the nearest (halves away from zero).

use serde_json::{Map, Value, json};

/// The six fields, in the order linear x, y, z then angular x, y, z.
pub const FIELDS: [&str; 6] = [
    "linear_x_mm_s",
    "linear_y_mm_s",
    "linear_z_mm_s",
    "angular_x_mrad_s",
    "angular_y_mrad_s",
    "angular_z_mrad_s",
];
const NAMES: [&str; 6] = ["linear.x", "linear.y", "linear.z", "angular.x", "angular.y", "angular.z"];

/// Six values in metres per second and radians per second become a command, or a reason
/// for refusing them. NaN and infinity are refused. So is any value whose magnitude,
/// after conversion, is above the limit: `limits` is (linear mm/s, angular mrad/s).
pub fn to_command(values: [f64; 6], limits: (i64, i64)) -> Result<Map<String, Value>, String> {
    let mut command = Map::new();
    for (i, v) in values.iter().enumerate() {
        let limit = if i < 3 { limits.0 } else { limits.1 };
        let scaled = (v * 1000.0).round();
        if !cfg!(feature = "planted-bug-twist-accepts-nonfinite") {
            if !v.is_finite() {
                return Err(format!("{} is not a finite number", NAMES[i]));
            }
            if scaled.abs() > limit as f64 {
                return Err(format!("{} is outside the configured limit of {limit}", NAMES[i]));
            }
        }
        command.insert(FIELDS[i].to_string(), json!(scaled as i64));
    }
    Ok(command)
}

/// A command back to six values in metres per second and radians per second. A field
/// that is absent or not an integer reads as zero.
pub fn from_command(command: &Map<String, Value>) -> [f64; 6] {
    let mut values = [0.0; 6];
    for (i, field) in FIELDS.iter().enumerate() {
        values[i] = command.get(*field).and_then(Value::as_i64).unwrap_or(0) as f64 / 1000.0;
    }
    values
}

#[cfg(test)]
#[cfg(not(feature = "planted-bug-twist-accepts-nonfinite"))]
mod tests {
    use super::*;

    const LIMITS: (i64, i64) = (5000, 10000);

    #[test]
    fn all_six_fields_are_carried_and_rounded_to_nearest() {
        let c = to_command([0.1234, -0.0005, 1.9996, 0.4, -0.0494, 0.0006], LIMITS).unwrap();
        let got: Vec<i64> = FIELDS.iter().map(|f| c[*f].as_i64().unwrap()).collect();
        assert_eq!(got, vec![123, -1, 2000, 400, -49, 1]);
    }

    #[test]
    fn nan_and_infinity_are_refused() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            for i in 0..6 {
                let mut v = [0.0; 6];
                v[i] = bad;
                assert!(to_command(v, LIMITS).is_err(), "field {i} with {bad}");
            }
        }
    }

    #[test]
    fn values_outside_the_limit_are_refused_and_the_limit_itself_is_accepted() {
        assert!(to_command([5.0, 0.0, 0.0, 0.0, 0.0, 10.0], LIMITS).is_ok());
        assert!(to_command([5.001, 0.0, 0.0, 0.0, 0.0, 0.0], LIMITS).is_err());
        assert!(to_command([0.0, -5.001, 0.0, 0.0, 0.0, 0.0], LIMITS).is_err());
        assert!(to_command([0.0, 0.0, 0.0, 0.0, 0.0, 10.001], LIMITS).is_err());
        assert!(to_command([1e300, 0.0, 0.0, 0.0, 0.0, 0.0], LIMITS).is_err());
    }

    #[test]
    fn a_command_converts_back_to_thousandths() {
        let c = to_command([0.1234567, 0.0, 0.0, 0.0, 0.0, -1.5], LIMITS).unwrap();
        assert_eq!(from_command(&c), [0.123, 0.0, 0.0, 0.0, 0.0, -1.5]);
        assert_eq!(from_command(&Map::new()), [0.0; 6]);
    }
}
