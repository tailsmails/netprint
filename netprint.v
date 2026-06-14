module main

import net
import time
import math
import term
import os
import rand

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h> 

struct C.timeval {
	tv_sec  i64
	tv_usec i64
}

struct C.tcp_info {
	tcpi_pmtu       u32
	tcpi_snd_mss    u32
	tcpi_rtt        u32
	tcpi_rcv_rtt    u32
	tcpi_rto        u32
	tcpi_snd_cwnd   u32
	tcpi_rttvar     u32
	tcpi_options    u8
}

fn C.close(fd int) int
fn C.setsockopt(fd int, level int, optname int, optval &void, optlen u32) int
fn C.getsockopt(fd int, level int, optname int, optval voidptr, optlen &u32) int

struct EnvBaseline {
mut:
	mean_rtt       f64 
	std_rtt        f64
	mean_ratio     f64 
	pmtu           u32
	snd_mss        u32
	kernel_rtt     u32
	kernel_rcv_rtt u32
	kernel_rto     u32
	kernel_cwnd    u32
	kernel_rttvar  u32
	tcp_opts       u8
	tls_ja4s       string
	tls_cert       string
}

fn write_u16(mut arr []u8, val int) {
	arr << u8((val >> 8) & 0xff)
	arr << u8(val & 0xff)
}

fn write_bytes(mut arr []u8, bytes []u8) {
	for b in bytes { arr << b }
}

fn build_tls_client_hello(sni string) []u8 {
	grease_values := [
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
	]
	
	grease_cipher_idx := rand.intn(grease_values.len) or { 0 }
	grease_cipher := grease_values[grease_cipher_idx]

	grease_ext_idx := rand.intn(grease_values.len) or { 1 }
	grease_ext := grease_values[grease_ext_idx]

	mut exts := []u8{}
	
	write_u16(mut exts, grease_ext)
	write_u16(mut exts, 0x0000) 
	
	write_u16(mut exts, 0x0000)
	sni_bytes := sni.bytes()
	write_u16(mut exts, sni_bytes.len + 5)
	write_u16(mut exts, sni_bytes.len + 3)
	exts << u8(0x00)
	write_u16(mut exts, sni_bytes.len)
	write_bytes(mut exts, sni_bytes)
	
	write_u16(mut exts, 0x0017)
	write_u16(mut exts, 0x0000)
	
	write_u16(mut exts, 0xff01)
	write_u16(mut exts, 0x0001)
	exts << u8(0x00)
	
	write_u16(mut exts, 0x000a)
	write_u16(mut exts, 0x0008)
	write_u16(mut exts, 0x0006)
	write_u16(mut exts, 0x001d) // Curve25519 (X25519)
	write_u16(mut exts, 0x0017) // secp256r1
	write_u16(mut exts, 0x0018) // secp384r1
	
	write_u16(mut exts, 0x000b)
	write_u16(mut exts, 0x0002)
	exts << u8(0x01)
	exts << u8(0x00) // Uncompressed point format
	
	write_u16(mut exts, 0x000d)
	write_u16(mut exts, 18)
	write_u16(mut exts, 16)
	write_u16(mut exts, 0x0403) // ecdsa_secp256r1_sha256
	write_u16(mut exts, 0x0503) // ecdsa_secp384r1_sha384
	write_u16(mut exts, 0x0603) // ecdsa_secp512r1_sha512
	write_u16(mut exts, 0x0804) // rsa_pss_rsae_sha256
	write_u16(mut exts, 0x0805) // rsa_pss_rsae_sha384
	write_u16(mut exts, 0x0806) // rsa_pss_rsae_sha512
	write_u16(mut exts, 0x0401) // rsa_pkcs1_sha256
	write_u16(mut exts, 0x0501) // rsa_pkcs1_sha384
	
	write_u16(mut exts, 0x0010)
	write_u16(mut exts, 14)
	write_u16(mut exts, 12)
	exts << u8(0x02)
	write_bytes(mut exts, 'h2'.bytes())
	exts << u8(0x08)
	write_bytes(mut exts, 'http/1.1'.bytes())
	
	mut hs := []u8{}
	write_u16(mut hs, 0x0303) // TLS 1.2
	
	for i in 0 .. 32 { 
		hs << u8((i * 13 + 47) & 0xff) 
	}
	
	hs << u8(0x20)
	for i in 0 .. 32 { 
		hs << u8((i * 17 + 29) & 0xff) 
	}
	
	ciphers := [
		u16(grease_cipher),
		0x1301, 0x1302, 0x1303, // TLS 1.3 Cipher Suites
		0xc02b, 0xc02f, 0xc02c, 0xc030,
		0xcca9, 0xcca8,
		0x009c, 0x009d
	]
	write_u16(mut hs, ciphers.len * 2)
	for c in ciphers { 
		write_u16(mut hs, int(c)) 
	}
	
	hs << u8(0x01) // Compression method: NULL
	hs << u8(0x00)
	
	write_u16(mut hs, exts.len)
	write_bytes(mut hs, exts)
	
	mut hs_hdr := []u8{}
	hs_hdr << u8(0x01) // Handshake Type: Client Hello
	hs_hdr << u8(hs.len >> 16)
	write_u16(mut hs_hdr, hs.len & 0xffff)
	write_bytes(mut hs_hdr, hs)
	
	mut record := []u8{}
	record << u8(0x16) // TLS Record Handshake Type
	write_u16(mut record, 0x0301)
	write_u16(mut record, hs_hdr.len)
	write_bytes(mut record, hs_hdr)
	return record
}

fn parse_tls(buf []u8, n int) (string, string) {
	mut ja4s := 'JA4S_ERR'
	mut cert_fp := 'NO_CERT'
	mut idx := 0
	for idx + 5 <= n {
		if buf[idx] != 0x16 { break }
		record_len := int((u32(buf[idx + 3]) << 8) | u32(buf[idx + 4]))
		if idx + 5 + record_len > n { break }
		mut hs_idx := idx + 5
		limit := idx + 5 + record_len
		for hs_idx + 4 <= limit {
			hs_type := buf[hs_idx]
			hs_len := int((u32(buf[hs_idx + 1]) << 16) | (u32(buf[hs_idx + 2]) << 8) | u32(buf[hs_idx + 3]))
			if hs_idx + 4 + hs_len > limit { break }
			if hs_type == 0x02 { 
				version := '${buf[hs_idx + 4]:02X}${buf[hs_idx + 5]:02X}'
				sid_len := int(buf[hs_idx + 38])
				cipher_idx := hs_idx + 39 + sid_len
				if cipher_idx + 1 < limit {
					cipher := '${buf[cipher_idx]:02X}${buf[cipher_idx + 1]:02X}'
					ja4s = 'JA4S_${version}_${cipher}'
				}
			} else if hs_type == 0x0b { 
				certs_len := int((u32(buf[hs_idx + 4]) << 16) | (u32(buf[hs_idx + 5]) << 8) | u32(buf[hs_idx + 6]))
				if certs_len > 0 && hs_idx + 10 <= limit {
					first_cert_len := int((u32(buf[hs_idx + 7]) << 16) | (u32(buf[hs_idx + 8]) << 8) | u32(buf[hs_idx + 9]))
					if first_cert_len > 0 && hs_idx + 10 + first_cert_len <= limit {
						mut hash := u32(2166136261)
						for j := 0; j < first_cert_len; j++ {
							hash = (hash ^ u32(buf[hs_idx + 10 + j])) * 16777619
						}
						cert_fp = 'CERT_${hash:08X}'
					}
				}
			}
			hs_idx += 4 + hs_len
		}
		idx += 5 + record_len
	}
	return ja4s, cert_fp
}

fn query_kernel_tcp_info(fd int) (u32, u32, u32, u32, u32, u32, u32, u8, int) {
	info := C.tcp_info{}
	mut len := u32(sizeof(C.tcp_info))
	
	res := C.getsockopt(fd, 6, 11, &info, &len)
	if res == 0 {
		return info.tcpi_pmtu, info.tcpi_snd_mss, info.tcpi_rtt, info.tcpi_rcv_rtt, info.tcpi_rto, info.tcpi_snd_cwnd, info.tcpi_rttvar, info.tcpi_options, 0
	} else {
		return 0, 0, 0, 0, 0, 0, 0, 0, int(C.errno)
	}
}

fn parse_tcp_options(opts u8) string {
	mut active := []string{}
	if (opts & 1) != 0 { active << 'TS' }      
	if (opts & 2) != 0 { active << 'SACK' }    
	if (opts & 4) != 0 { active << 'WSCALE' }  
	if (opts & 8) != 0 { active << 'ECN' }     
	if (opts & 16) != 0 { active << 'ECN_SEEN'} 
	if (opts & 32) != 0 { active << 'TFO' }    
	if active.len == 0 { return 'NONE' }
	return active.join('+')
}

fn is_private_ip(ip string) bool {
	parts := ip.split('.')
	if parts.len != 4 { return false }
	p0 := parts[0].int()
	p1 := parts[1].int()
	if p0 == 10 { return true }
	if p0 == 172 && p1 >= 16 && p1 <= 31 { return true }
	if p0 == 192 && p1 == 168 { return true }
	if p0 == 127 { return true }
	if p0 == 0 { return true }
	return false
}

fn probe_environment(host string, port int) !(f64, f64, u32, u32, u32, u32, u32, u32, u32, u8, int, string, string, string) {
	addrs := net.resolve_addrs_fuzzy(host, .tcp)!
	if addrs.len == 0 { return error('DNS resolution is empty') }
	current_ip := addrs[0].str().split(':')[0]

	mut sw := time.new_stopwatch()
	mut conn := net.dial_tcp('${current_ip}:${port}')!
	rtt_tcp := f64(sw.elapsed().microseconds()) / 1000.0 
	conn.close() or {}
	
	mut conn_tls := net.dial_tcp('${current_ip}:${port}')!
	conn_tls.set_read_timeout(3 * time.second)
	
	payload := build_tls_client_hello(host)
	
	sw.restart()
	conn_tls.write(payload) or {}
	
	mut buf := []u8{len: 32768}
	mut total_read := 0
	mut ja4s := 'JA4S_ERR'
	mut cert := 'NO_CERT'
	mut rtt_tls := 0.0
	
	for total_read < 32768 {
		mut temp := []u8{len: 4096}
		n := conn_tls.read(mut temp) or { break }
		if n <= 0 { break }
		
		if total_read == 0 {
			rtt_tls = f64(sw.elapsed().microseconds()) / 1000.0
		}
		
		for i in 0 .. n {
			if total_read < 32768 {
				buf[total_read] = temp[i]
				total_read++
			}
		}
		if total_read >= 5 {
			j_parsed, c_parsed := parse_tls(buf[0..total_read], total_read)
			if c_parsed != 'NO_CERT' {
				ja4s = j_parsed
				cert = c_parsed
				break 
			}
			ja4s = j_parsed
		}
	}

	pmtu, mss, k_r, k_rcv, k_rto, k_cwnd, k_rttvar, tcp_opts, err_code := query_kernel_tcp_info(conn_tls.sock.handle)
	
	conn_tls.close() or {}
	
	return rtt_tcp, rtt_tls, pmtu, mss, k_r, k_rcv, k_rto, k_cwnd, k_rttvar, tcp_opts, err_code, ja4s, cert, current_ip
}

fn main() {
	println(term.bold('= NetPrint ='))

	mut targets := []string{}

	if os.args.len > 1 {
		targets = os.args[1..].clone()
	} else {
		println('[*] No CLI targets provided.')
		input := os.input('[?] Enter targets separated by spaces (e.g. google.com cloudflare.com):\n> ')
		trimmed := input.trim_space()
		if trimmed != '' {
			raw_parts := trimmed.split(' ')
			for part in raw_parts {
				if part.trim_space() != '' {
					targets << part.trim_space()
				}
			}
		} else {
			targets = ['google.com', 'cloudflare.com']
		}
	}

	println('[*] Configured Monitoring Targets: ${targets}')
	target_port := 443

	mut baselines := map[string]EnvBaseline{}

	for target in targets {
		println('\n' + term.bold('[*] Performing pre-flight DNS validation for ${target}...'))
		_ := net.resolve_addrs_fuzzy(target, .tcp) or {
			eprintln(term.red('[FATAL] DNS resolution failed for ${target}. Skipping this target.'))
			continue
		}

		println('[*] Running 10-Cycle Calibration for ${target}...')
		mut rtts := []f64{}
		mut ratios := []f64{}
		mut pmtus := []u32{}
		mut msses := []u32{}
		mut k_rtts := []u32{}
		mut k_rcv_rtts := []u32{}
		mut k_rtos := []u32{}
		mut k_cwnds := []u32{}
		mut k_rttvars := []u32{}
		mut k_tcp_opts := []u8{}
		mut final_ja4s := ''
		mut final_cert := ''

		for i in 0 .. 10 {
			rtt_tcp, rtt_tls, pmtu, mss, k_r, k_rcv, k_rto, k_cwnd, k_rttvar, tcp_opts, err_code, ja4s, cert, _ := probe_environment(target, target_port) or {
				eprintln(term.yellow('[WARN] Cycle ${i+1} dropped for ${target}. Retrying...'))
				time.sleep(500 * time.millisecond)
				continue
			}
			if err_code != 0 {
				eprintln(term.red('[DEBUG] getsockopt failed with errno: ${err_code}'))
			}
			rtts << rtt_tcp
			if rtt_tcp > 0 { ratios << (rtt_tls / rtt_tcp) }
			if pmtu > 0 { pmtus << pmtu }
			if mss > 0 { msses << mss }
			if k_r > 0 { k_rtts << k_r }
			if k_rcv > 0 { k_rcv_rtts << k_rcv }
			if k_rto > 0 { k_rtos << k_rto }
			if k_cwnd > 0 { k_cwnds << k_cwnd }
			if k_rttvar > 0 { k_rttvars << k_rttvar }
			if tcp_opts > 0 { k_tcp_opts << tcp_opts }
			final_ja4s = ja4s
			final_cert = cert
			time.sleep(200 * time.millisecond)
		}

		if rtts.len < 5 {
			eprintln(term.red('[FATAL] Inadequate calibration samples collected for ${target}. Skipping.'))
			continue
		}

		mut sum_rtt := 0.0
		for r in rtts { sum_rtt += r }
		mean_rtt := sum_rtt / f64(rtts.len)

		mut sum_sq_diff := 0.0
		for r in rtts { sum_sq_diff += math.pow(r - mean_rtt, 2) }
		std_rtt := math.sqrt(sum_sq_diff / f64(rtts.len))

		mut sum_ratio := 0.0
		for rat in ratios { sum_ratio += rat }
		mean_ratio := sum_ratio / f64(ratios.len)

		base_pmtu := if pmtus.len > 0 { pmtus[pmtus.len - 1] } else { u32(1500) }
		base_mss := if msses.len > 0 { msses[msses.len - 1] } else { u32(1460) }
		base_k_rtt := if k_rtts.len > 0 { k_rtts[k_rtts.len - 1] } else { u32(0) }
		base_k_rcv := if k_rcv_rtts.len > 0 { k_rcv_rtts[k_rcv_rtts.len - 1] } else { u32(0) }
		base_k_rto := if k_rtos.len > 0 { k_rtos[k_rtos.len - 1] } else { u32(0) }
		base_k_cwnd := if k_cwnds.len > 0 { k_cwnds[k_cwnds.len - 1] } else { u32(0) }
		base_k_rttvar := if k_rttvars.len > 0 { k_rttvars[k_rttvars.len - 1] } else { u32(0) }
		base_tcp_opts := if k_tcp_opts.len > 0 { k_tcp_opts[k_tcp_opts.len - 1] } else { u8(0) }

		baselines[target] = EnvBaseline{
			mean_rtt: mean_rtt
			std_rtt: std_rtt
			mean_ratio: mean_ratio
			pmtu: base_pmtu
			snd_mss: base_mss
			kernel_rtt: base_k_rtt
			kernel_rcv_rtt: base_k_rcv
			kernel_rto: base_k_rto
			kernel_cwnd: base_k_cwnd
			kernel_rttvar: base_k_rttvar
			tcp_opts: base_tcp_opts
			tls_ja4s: final_ja4s
			tls_cert: final_cert
		}

		println('\n' + term.bold(term.green('[+] Side-Channel Calibration Complete for ${target}:')))
		println('    TCP Connect RTT:  ${term.cyan('${baselines[target].mean_rtt:.2f} ms')} (StdDev: ${term.gray('${baselines[target].std_rtt:.2f}')})')
		println('    Handshake Ratio:  ${term.cyan('${baselines[target].mean_ratio:.3f}x')} (TLS/TCP delay ratio)')
		println('    Kernel Peer RTT:  ${term.cyan('${(f64(baselines[target].kernel_rtt)/1000.0):.2f} ms')}')
		println('    Receiver RTT:     ${term.cyan('${(f64(baselines[target].kernel_rcv_rtt)/1000.0):.2f} ms')}')
		println('    Retransmit RTO:   ${term.cyan('${(f64(baselines[target].kernel_rto)/1000.0):.2f} ms')}')
		println('    Kernel CWND Size: ${term.cyan('${baselines[target].kernel_cwnd}')}')
		println('    Kernel RTT Var:   ${term.cyan('${(f64(baselines[target].kernel_rttvar)/1000.0):.2f} ms')}')
		println('    Path MTU:         ${term.cyan('${baselines[target].pmtu} bytes')} | MSS: ${term.cyan('${baselines[target].snd_mss} bytes')}')
		println('    TCP Options:      ${term.cyan(parse_tcp_options(baselines[target].tcp_opts))}')
		println('    JA4S Fingerprint: ${term.yellow(baselines[target].tls_ja4s)}')
		println('    Cert Signature:   ${term.yellow(baselines[target].tls_cert)}\n')
	}

	if baselines.len == 0 {
		eprintln(term.red('[FATAL] No targets were successfully calibrated. Exiting.'))
		exit(1)
	}

	println(term.gray('[*] Integrity lock engaged. Continuous passive scanning active...'))

	for {
		jitter_ms := rand.int_in_range(2000, 5001) or { 3000 }
		time.sleep(jitter_ms * time.millisecond)
		
		for target, baseline in baselines {
			rtt_tcp, rtt_tls, pmtu, mss, k_r, k_rcv, k_rto, k_cwnd, _, tcp_opts, err_code, ja4s, cert, current_ip := probe_environment(target, target_port) or {
				println(term.yellow('[!] [${target}] Socket session dropped (Transient network jitter or packet rejection)'))
				continue
			}
			if err_code != 0 {
				println(term.red('[DEBUG] [${target}] runtime getsockopt failed with errno: ${err_code}'))
			}

			mut anomaly_score := 0
			mut reasons := []string{}

			current_ratio := if rtt_tcp > 0 { rtt_tls / rtt_tcp } else { 1.0 }
			if rtt_tcp < 4.0 && current_ratio > (baseline.mean_ratio * 3.5) && rtt_tls > 30.0 {
				anomaly_score += 45
				reasons << 'Latency Asymmetry Detected: Ultra-low TCP connection RTT (${rtt_tcp:.1f}ms) with high TLS handshake RTT (${rtt_tls:.1f}ms). Handshake delay ratio: ${current_ratio:.1f}x (Expected: ${baseline.mean_ratio:.1f}x). Strong indicator of early TCP termination proxy.'
			}

			if pmtu != 0 && baseline.pmtu != 0 && pmtu != baseline.pmtu {
				anomaly_score += 25
				reasons << 'Path MTU Shift: PMTU migrated from ${baseline.pmtu} to ${pmtu}. Indicates active path re-routing or packet resizing by inline network hardware.'
			}
			if mss != 0 && baseline.snd_mss != 0 && mss != baseline.snd_mss {
				anomaly_score += 20
				reasons << 'Segment Size Shift: MSS mutated from ${baseline.snd_mss} to ${mss}. Probable TCP header rewriting or segment-level middlebox intervention.'
			}

			if k_rcv > 0 && baseline.kernel_rcv_rtt > 0 {
				rcv_diff := math.abs(f64(k_rcv) - f64(baseline.kernel_rcv_rtt)) / 1000.0
				if rcv_diff > 150.0 && rtt_tcp < 10.0 {
					anomaly_score += 15
					reasons << 'Receiver RTT Drift: Kernel tcpi_rcv_rtt deviated by ${rcv_diff:.1f}ms on local routing, indicating delayed ACK handling by the peer.'
				}
			}

			if tcp_opts != 0 && baseline.tcp_opts != 0 && tcp_opts != baseline.tcp_opts {
				anomaly_score += 30
				reasons << 'TCP Options Mismatch: Negotiated options shifted from ${parse_tcp_options(baseline.tcp_opts)} to ${parse_tcp_options(tcp_opts)}. Indicates a transport-layer rewriting proxy.'
			}

			if ja4s != baseline.tls_ja4s {
				anomaly_score += 35
				reasons << 'TLS Fingerprint Mismatch: Cryptographic handshake signature altered. Expected: ${baseline.tls_ja4s}, Got: ${ja4s}. Indicates downstream TLS protocol renegotiation.'
			}
			if cert != baseline.tls_cert && cert != 'NO_CERT' && baseline.tls_cert != 'NO_CERT' {
				anomaly_score += 50
				reasons << 'TLS Certificate Mismatch: Handshake returned an altered certificate hash (Expected: ${baseline.tls_cert}, Got: ${cert}). Highly indicative of active SSL/TLS interception/decryption proxy.'
			}

			if is_private_ip(current_ip) {
				anomaly_score += 50
				reasons << 'DNS Resolution Divergence: Host resolved to a private/loopback RFC1918 address [${current_ip}]. Indicates local DNS spoofing or routing hijack.'
			}

			now_str := time.now().format_ss()
			if anomaly_score == 0 {
				println('[${now_str}] [${target}] ${term.green('[SECURE]')} RTT-TCP:${rtt_tcp:.1f}ms | Ratio:${current_ratio:.2f}x | k_RTT:${(f64(k_r)/1000.0):.2f}ms | k_RTO:${(f64(k_rto)/1000.0):.1f}ms | CWND:${k_cwnd} | TCP-Opts:${parse_tcp_options(tcp_opts)}')
			} else if anomaly_score >= 40 {
				println('\n[${now_str}] [${target}] ${term.bold(term.red('[!!! SYSTEM PATH ANOMALY DETECTED !!!]'))}')
				println(' -> Cumulative Deviation Index: ${term.red('-${anomaly_score}')}')
				for r in reasons {
					println(' -> ${term.yellow(r)}')
				}
				println('===========================================================\n')
			} else {
				println('[${now_str}] [${target}] ${term.yellow('[WARN: CONTEXTUAL JITTER DETECTED]')} -> ${reasons[0]}')
			}
		}
	}
}
