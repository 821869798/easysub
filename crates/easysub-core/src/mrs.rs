//! Mihomo MRS encoding.

use std::{
    collections::{BTreeSet, VecDeque},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;

use crate::{
    error::{AppError, Result},
    model::RuleBehavior,
};

const MAGIC: &[u8; 4] = b"MRS\x01";

pub fn encode(rules: &[String], behavior: RuleBehavior) -> Result<Vec<u8>> {
    if rules.is_empty() {
        return Err(AppError::Conversion(
            "cannot encode an empty ruleset".into(),
        ));
    }
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3)
        .map_err(|error| AppError::Conversion(format!("zstd initialization failed: {error}")))?;
    encoder.write_all(MAGIC).map_err(io_error)?;
    encoder
        .write_all(&[match behavior {
            RuleBehavior::Domain => 0,
            RuleBehavior::IpCidr => 1,
        }])
        .map_err(io_error)?;
    write_i64(&mut encoder, rules.len() as i64)?;
    write_i64(&mut encoder, 0)?;
    match behavior {
        RuleBehavior::Domain => write_domain_payload(&mut encoder, rules)?,
        RuleBehavior::IpCidr => write_ipcidr_payload(&mut encoder, rules)?,
    }
    encoder
        .finish()
        .map_err(|error| AppError::Conversion(format!("zstd finalization failed: {error}")))
}

fn write_domain_payload(writer: &mut impl Write, rules: &[String]) -> Result<()> {
    let mut keys = BTreeSet::<Vec<u8>>::new();
    for rule in rules {
        let normalized = rule.trim().to_ascii_lowercase();
        if let Some(suffix) = normalized.strip_prefix("+.") {
            if !suffix.is_empty() {
                keys.insert(suffix.chars().rev().collect::<String>().into_bytes());
                keys.insert(normalized.chars().rev().collect::<String>().into_bytes());
            }
        } else if !normalized.is_empty() {
            keys.insert(normalized.chars().rev().collect::<String>().into_bytes());
        }
    }
    if keys.is_empty() {
        return Err(AppError::Conversion(
            "domain ruleset is empty after validation".into(),
        ));
    }
    let keys: Vec<Vec<u8>> = keys.into_iter().collect();
    let (leaves, label_bitmap, labels) = build_succinct_set(&keys);
    writer.write_all(&[1]).map_err(io_error)?;
    write_u64_vec(writer, &leaves)?;
    write_u64_vec(writer, &label_bitmap)?;
    write_i64(writer, labels.len() as i64)?;
    writer.write_all(&labels).map_err(io_error)
}

fn build_succinct_set(keys: &[Vec<u8>]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    let mut leaves = Vec::new();
    let mut label_bitmap = Vec::new();
    let mut labels = Vec::new();
    let mut label_index = 0usize;
    let mut queue = VecDeque::from([(0usize, keys.len(), 0usize)]);
    let mut node_index = 0usize;

    while let Some((mut start, end, column)) = queue.pop_front() {
        if column == keys[start].len() {
            start += 1;
            set_bit(&mut leaves, node_index);
        }
        let mut cursor = start;
        while cursor < end {
            let group_start = cursor;
            let label = keys[group_start][column];
            while cursor < end && keys[cursor][column] == label {
                cursor += 1;
            }
            queue.push_back((group_start, cursor, column + 1));
            labels.push(label);
            label_index += 1;
        }
        set_bit(&mut label_bitmap, label_index);
        label_index += 1;
        node_index += 1;
    }
    (leaves, label_bitmap, labels)
}

fn write_ipcidr_payload(writer: &mut impl Write, rules: &[String]) -> Result<()> {
    let mut v4 = Vec::<(u32, u32)>::new();
    let mut v6 = Vec::<(u128, u128)>::new();
    for rule in rules {
        match rule.parse::<IpNet>() {
            Ok(IpNet::V4(net)) => {
                let start = u32::from(net.network());
                let host_bits = 32 - u32::from(net.prefix_len());
                let end = start
                    | if host_bits == 32 {
                        u32::MAX
                    } else {
                        (1u32 << host_bits) - 1
                    };
                v4.push((start, end));
            }
            Ok(IpNet::V6(net)) => {
                let start = u128::from(net.network());
                let host_bits = 128 - u32::from(net.prefix_len());
                let end = start
                    | if host_bits == 128 {
                        u128::MAX
                    } else {
                        (1u128 << host_bits) - 1
                    };
                v6.push((start, end));
            }
            Err(error) => {
                return Err(AppError::Conversion(format!(
                    "invalid CIDR {rule}: {error}"
                )));
            }
        }
    }
    let v4 = merge_ranges(v4);
    let v6 = merge_ranges(v6);
    writer.write_all(&[1]).map_err(io_error)?;
    write_i64(writer, (v4.len() + v6.len()) as i64)?;
    for (start, end) in v4 {
        writer
            .write_all(&mapped_v4(Ipv4Addr::from(start)))
            .map_err(io_error)?;
        writer
            .write_all(&mapped_v4(Ipv4Addr::from(end)))
            .map_err(io_error)?;
    }
    for (start, end) in v6 {
        writer
            .write_all(&Ipv6Addr::from(start).octets())
            .map_err(io_error)?;
        writer
            .write_all(&Ipv6Addr::from(end).octets())
            .map_err(io_error)?;
    }
    Ok(())
}

fn merge_ranges<T>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)>
where
    T: Copy + Ord + num_traits::CheckedAdd + num_traits::One,
{
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            let adjacent = last
                .1
                .checked_add(&T::one())
                .is_some_and(|next| start <= next);
            if start <= last.1 || adjacent {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn mapped_v4(address: Ipv4Addr) -> [u8; 16] {
    address.to_ipv6_mapped().octets()
}

fn write_u64_vec(writer: &mut impl Write, values: &[u64]) -> Result<()> {
    write_i64(writer, values.len() as i64)?;
    for value in values {
        writer.write_all(&value.to_be_bytes()).map_err(io_error)?;
    }
    Ok(())
}

fn write_i64(writer: &mut impl Write, value: i64) -> Result<()> {
    writer.write_all(&value.to_be_bytes()).map_err(io_error)
}

fn set_bit(bitmap: &mut Vec<u64>, index: usize) {
    while index / 64 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index / 64] |= 1 << (index % 64);
}

fn io_error(error: std::io::Error) -> AppError {
    AppError::Conversion(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn decode(encoded: &[u8]) -> Vec<u8> {
        let mut decoder = zstd::stream::Decoder::new(encoded).unwrap();
        let mut output = Vec::new();
        decoder.read_to_end(&mut output).unwrap();
        output
    }

    #[test]
    fn writes_domain_header_and_payload() {
        let encoded = encode(
            &["example.com".into(), "+.google.com".into()],
            RuleBehavior::Domain,
        )
        .unwrap();
        let bytes = decode(&encoded);
        assert_eq!(
            to_hex(&bytes),
            "4d5253010000000000000000020000000000000000010000000000000001000000000003200000000000000000010000000755554aaa00000000000000116d6f632e656c67706f6d6f6167782e652b"
        );
    }

    #[test]
    fn merges_adjacent_ip_ranges() {
        let encoded = encode(
            &[
                "10.0.0.0/9".into(),
                "10.128.0.0/9".into(),
                "2001:db8::/126".into(),
            ],
            RuleBehavior::IpCidr,
        )
        .unwrap();
        let bytes = decode(&encoded);
        assert_eq!(
            to_hex(&bytes),
            "4d525301010000000000000003000000000000000001000000000000000200000000000000000000ffff0a00000000000000000000000000ffff0affffff20010db800000000000000000000000020010db8000000000000000000000003"
        );
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
