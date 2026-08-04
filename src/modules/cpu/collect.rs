use std::fs;

use crate::core::error::ModuleError;

/// Raw facts read from the system, before any interpretation. See
/// ARCHITECTURE.md "Collectors".
#[derive(Debug, Clone, PartialEq)]
pub struct CpuRawData {
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub model_name: Option<String>,
}

/// Thin I/O wrapper: reads the two source files and delegates all
/// interpretation to the pure parse functions below.
pub fn collect() -> Result<CpuRawData, ModuleError> {
    let loadavg_text = fs::read_to_string("/proc/loadavg").map_err(|source| ModuleError::Io {
        path: "/proc/loadavg".to_string(),
        source,
    })?;
    let (load_1m, load_5m, load_15m) = parse_loadavg(&loadavg_text)?;

    // /proc/cpuinfo's "model name" field is x86-specific and absent (or
    // named differently) on some architectures — treat it as optional
    // rather than failing the whole module over cosmetic evidence.
    let model_name = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| parse_model_name(&text));

    Ok(CpuRawData {
        load_1m,
        load_5m,
        load_15m,
        model_name,
    })
}

/// Parse `/proc/loadavg`, e.g. "0.52 0.58 0.59 1/234 5678". Pure function,
/// tested directly against fixture strings.
pub fn parse_loadavg(text: &str) -> Result<(f64, f64, f64), ModuleError> {
    let mut fields = text.trim().split_whitespace();
    let parse_next = |fields: &mut std::str::SplitWhitespace, which: &str| {
        fields
            .next()
            .ok_or_else(|| ModuleError::Parse {
                what: "/proc/loadavg".to_string(),
                reason: format!("missing {which} field"),
            })
            .and_then(|s| {
                s.parse::<f64>().map_err(|e| ModuleError::Parse {
                    what: "/proc/loadavg".to_string(),
                    reason: format!("{which} field '{s}': {e}"),
                })
            })
    };
    let load_1m = parse_next(&mut fields, "load_1m")?;
    let load_5m = parse_next(&mut fields, "load_5m")?;
    let load_15m = parse_next(&mut fields, "load_15m")?;
    Ok((load_1m, load_5m, load_15m))
}

/// Parse the first "model name" line out of `/proc/cpuinfo` text.
pub fn parse_model_name(cpuinfo_text: &str) -> Option<String> {
    for line in cpuinfo_text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == "model name" {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loadavg_fields() {
        let (l1, l5, l15) = parse_loadavg("0.52 0.58 0.59 1/234 5678\n").unwrap();
        assert_eq!(l1, 0.52);
        assert_eq!(l5, 0.58);
        assert_eq!(l15, 0.59);
    }

    #[test]
    fn errors_on_missing_fields() {
        assert!(parse_loadavg("0.52 0.58").is_err());
    }

    #[test]
    fn errors_on_non_numeric_field() {
        assert!(parse_loadavg("not-a-number 0.58 0.59 1/1 1").is_err());
    }

    #[test]
    fn parses_model_name() {
        let text = "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Processor @ 2.10GHz\ncache size\t: 33792 KB\n";
        assert_eq!(
            parse_model_name(text),
            Some("Intel(R) Xeon(R) Processor @ 2.10GHz".to_string())
        );
    }

    #[test]
    fn model_name_absent_returns_none() {
        let text = "processor\t: 0\nBogoMIPS\t: 4199.99\n";
        assert_eq!(parse_model_name(text), None);
    }
}
