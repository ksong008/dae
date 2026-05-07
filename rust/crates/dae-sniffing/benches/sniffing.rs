use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use dae_sniffing::{
    QuicSniffScratch, sniff_http_host_ref, sniff_quic_initial_sni, sniff_quic_initial_sni_ref,
    sniff_tls_sni_ref,
};

fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

fn go_hex_const(source: &'static str, name: &str) -> &'static str {
    let prefix = format!("var {name}, _ = hex.DecodeString(\"");
    let start = source.find(&prefix).unwrap() + prefix.len();
    let tail = &source[start..];
    let end = tail.find('"').unwrap();
    &tail[..end]
}

fn decode_go_tls_hex_const(name: &str) -> Vec<u8> {
    decode_hex(go_hex_const(
        include_str!("../../../../component/sniffing/tls_test.go"),
        name,
    ))
}

fn decode_go_quic_hex_const(name: &str) -> Vec<u8> {
    decode_hex(go_hex_const(
        include_str!("../../../../component/sniffing/quic_test.go"),
        name,
    ))
}

fn criterion_benchmark(c: &mut Criterion) {
    let http = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    c.bench_function("http_host_ref", |b| {
        b.iter(|| {
            let host = sniff_http_host_ref(black_box(http)).expect("sniff http host");
            black_box(host);
        });
    });

    let tls = decode_go_tls_hex_const("tlsStreamGoogle");
    c.bench_function("tls_sni_ref", |b| {
        b.iter(|| {
            let sni = sniff_tls_sni_ref(black_box(&tls)).expect("sniff tls sni");
            black_box(sni);
        });
    });

    let quic1 = decode_go_quic_hex_const("QuicStream2_1");
    let quic2 = decode_go_quic_hex_const("QuicStream2_2");
    let packets = [&quic1[..], &quic2[..]];
    assert_eq!(sniff_quic_initial_sni(&packets).unwrap(), "i.ytimg.com");

    c.bench_function("quic_initial_sni_owned", |b| {
        b.iter(|| {
            let sni = sniff_quic_initial_sni(black_box(&packets)).expect("sniff quic sni");
            black_box(sni);
        });
    });

    let mut scratch = QuicSniffScratch::new();
    assert_eq!(
        sniff_quic_initial_sni_ref(&packets, &mut scratch).unwrap(),
        "i.ytimg.com"
    );

    c.bench_function("quic_initial_sni_ref_reuse_scratch", |b| {
        b.iter(|| {
            let sni = sniff_quic_initial_sni_ref(black_box(&packets), black_box(&mut scratch))
                .expect("sniff quic sni");
            black_box(sni);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
