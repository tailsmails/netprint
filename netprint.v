import os
import net
import time
import math

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>

struct C.timeval {
	tv_sec  i64
	tv_usec i64
}

fn C.socket(domain int, type_ int, protocol int) int
fn C.recvfrom(sock int, buf voidptr, len int, flags int, src_addr voidptr, addrlen voidptr) int
fn C.setsockopt(sock int, level int, optname int, optval voidptr, optlen int) int
fn C.close(fd int) int
fn C.geteuid() int

const af_inet = 2
const sock_raw = 3
const ipproto_tcp = 6
const sol_socket = 1
const so_rcvtimeo = 20

struct NetworkProfile {
	rtt       i64
	ip_ttl    int
	ip_tos    int
	ip_df     bool
	ip_id     u16
	tcp_win   int
	tcp_opts  string
	tcp_tsval u32
	tls_ja4s  string
	tls_cert  string
	dns_bad   bool
	pmtu      int
}

fn write_u16(mut arr []u8, val int) {
	arr << u8((val >> 8) & 0xff)
	arr << u8(val & 0xff)
}

fn write_bytes(mut arr []u8, bytes []u8) {
	for b in bytes {
		arr << b
	}
}

fn build_dynamic_client_hello(sni string) []u8 {
	mut exts := []u8{}
	write_u16(mut exts, 0x0000)
	sni_bytes := sni.bytes()
	write_u16(mut exts, sni_bytes.len + 5)
	write_u16(mut exts, sni_bytes.len + 3)
	exts << u8(0x00)
	write_u16(mut exts, sni_bytes.len)
	write_bytes(mut exts, sni_bytes)
	write_u16(mut exts, 0x000a)
	write_u16(mut exts, 8)
	write_u16(mut exts, 6)
	write_u16(mut exts, 0x001d)
	write_u16(mut exts, 0x0017)
	write_u16(mut exts, 0x0018)
	write_u16(mut exts, 0x000d)
	write_u16(mut exts, 10)
	write_u16(mut exts, 8)
	write_u16(mut exts, 0x0403)
	write_u16(mut exts, 0x0503)
	write_u16(mut exts, 0x0603)
	write_u16(mut exts, 0x0804)
	write_u16(mut exts, 0x0010)
	write_u16(mut exts, 14)
	write_u16(mut exts, 12)
	exts << u8(2)
	exts << u8(0x68)
	exts << u8(0x32)
	exts << u8(8)
	exts << u8(0x68)
	exts << u8(0x74)
	exts << u8(0x74)
	exts << u8(0x70)
	exts << u8(0x2f)
	exts << u8(0x31)
	exts << u8(0x2e)
	exts << u8(0x31)
	
	mut hs := []u8{}
	write_u16(mut hs, 0x0303)
	for i in 0 .. 32 {
		hs << u8(i + 1)
	}
	hs << u8(0x00)
	ciphers := [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8]
	write_u16(mut hs, ciphers.len * 2)
	for c in ciphers {
		write_u16(mut hs, c)
	}
	hs << u8(0x01)
	hs << u8(0x00)
	write_u16(mut hs, exts.len)
	write_bytes(mut hs, exts)
	
	mut hs_hdr := []u8{}
	hs_hdr << u8(0x01)
	hs_hdr << u8(hs.len >> 16)
	write_u16(mut hs_hdr, hs.len & 0xffff)
	write_bytes(mut hs_hdr, hs)
	
	mut record := []u8{}
	record << u8(0x16)
	write_u16(mut record, 0x0301)
	write_u16(mut record, hs_hdr.len)
	write_bytes(mut record, hs_hdr)
	return record
}

fn parse_tls_records(buf []u8, n int) (string, string) {
	mut ja4s := 'ERR_HANDSHAKE'
	mut cert_fp := 'NO_CERT'
	mut idx := 0
	for idx + 5 <= n {
		content_type := buf[idx]
		if content_type != 0x16 {
			break
		}
		record_len := int((u32(buf[idx + 3]) << 8) | u32(buf[idx + 4]))
		if idx + 5 + record_len > n {
			break
		}
		mut hs_idx := idx + 5
		limit := idx + 5 + record_len
		for hs_idx + 4 <= limit {
			hs_type := buf[hs_idx]
			hs_len := int((u32(buf[hs_idx + 1]) << 16) | (u32(buf[hs_idx + 2]) << 8) | u32(buf[hs_idx + 3]))
			if hs_idx + 4 + hs_len > limit {
				break
			}
			if hs_type == 0x02 {
				version := '${buf[hs_idx + 4]:02X}${buf[hs_idx + 5]:02X}'
				sid_len := int(buf[hs_idx + 38])
				cipher_idx := hs_idx + 39 + sid_len
				if cipher_idx + 1 < limit {
					cipher := '${buf[cipher_idx]:02X}${buf[cipher_idx + 1]:02X}'
					mut ext_list := []string{}
					ext_len_idx := cipher_idx + 3
					if ext_len_idx + 1 < limit {
						ext_total_len := int((u32(buf[ext_len_idx]) << 8) | u32(buf[ext_len_idx + 1]))
						mut current_idx := ext_len_idx + 2
						for current_idx + 3 < limit && current_idx < ext_len_idx + 2 + ext_total_len {
							ext_type := '${buf[current_idx]:02X}${buf[current_idx + 1]:02X}'
							ext_len := int((u32(buf[current_idx + 2]) << 8) | u32(buf[current_idx + 3]))
							ext_list << ext_type
							current_idx += 4 + ext_len
						}
					}
					ext_str := if ext_list.len > 0 { ext_list.join('-') } else { 'NOEXT' }
					ja4s = 'JA4S_${version}_${cipher}_${ext_str}'
				}
			} else if hs_type == 0x0b {
				certs_total_len := int((u32(buf[hs_idx + 4]) << 16) | (u32(buf[hs_idx + 5]) << 8) | u32(buf[hs_idx + 6]))
				if certs_total_len > 0 && hs_idx + 7 + certs_total_len <= limit {
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

fn get_deep_tls_fingerprint(host string, port int) (string, string) {
	mut conn := net.dial_tcp('${host}:${port}') or { return 'ERR_CONN', 'ERR_CONN' }
	defer { conn.close() or {} }
	conn.set_read_timeout(3 * time.second)
	conn.set_write_timeout(3 * time.second)

	payload := build_dynamic_client_hello(host)
	conn.write(payload) or { return 'ERR_WRITE', 'ERR_WRITE' }
	mut buf := []u8{len: 32768}
	mut total_read := 0
	for total_read < 32768 {
		mut temp := []u8{len: 4096}
		n := conn.read(mut temp) or { break }
		if n <= 0 { break }
		for i in 0 .. n {
			if total_read < 32768 {
				buf[total_read] = temp[i]
				total_read++
			}
		}
		if total_read >= 5 {
			ja4s, cert_fp := parse_tls_records(buf[0..total_read], total_read)
			if cert_fp != 'NO_CERT' {
				return ja4s, cert_fp
			}
		}
	}
	return parse_tls_records(buf[0..total_read], total_read)
}

fn resolve_host(host string) string {
	parts := host.split('.')
	if parts.len == 4 {
		mut is_ip := true
		for p in parts {
			if p.int() < 0 || p.int() > 255 {
				is_ip = false
			}
		}
		if is_ip {
			return host
		}
	}
	res := os.execute('ping -c 1 -W 2 ${host}')
	for line in res.output.split('\n') {
		if line.contains('PING') {
			p1 := line.split('(')
			if p1.len > 1 {
				p2 := p1[1].split(')')
				if p2.len > 0 {
					return p2[0]
				}
			}
		}
	}
	return ''
}

fn capture_deep_packet_signature(target_ip string, target_port int) (int, int, bool, int, string, u32, u16) {
	sock := C.socket(af_inet, sock_raw, ipproto_tcp)
	if sock < 0 {
		return -1, -1, false, -1, 'ERR_SOCKET', 0, 0
	}
	defer { C.close(sock) }
	
	tv := C.timeval{tv_sec: 2, tv_usec: 0}
	C.setsockopt(sock, sol_socket, so_rcvtimeo, &tv, sizeof(C.timeval))
	mut buf := []u8{len: 2048}
	
	for {
		n := C.recvfrom(sock, buf.data, 2048, 0, C.NULL, C.NULL)
		if n < 40 { break }
		
		ihl := (buf[0] & 0x0F) * 4
		if ihl < 20 || ihl + 20 > n { continue }
		
		src_ip := '${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}'
		if src_ip != target_ip { continue }
		
		src_p := int((u32(buf[ihl]) << 8) | u32(buf[ihl+1]))
		if src_p != target_port { continue }
		
		flags := buf[ihl+13]
		if (flags & 0x12) == 0x12 {
			ip_tos := int(buf[1])
			ip_df  := (buf[6] & 0x40) != 0
			ip_ttl := int(buf[8])
			ip_id  := (u16(buf[4]) << 8) | u16(buf[5])
			
			win_size := int((u32(buf[ihl+14]) << 8) | u32(buf[ihl+15]))
			tcp_hdr_len := (buf[ihl+12] >> 4) * 4
			
			mut opts := []string{}
			mut ts_val := u32(0)
			
			if (flags & 0x40) != 0 { opts << 'E' }
			if (flags & 0x80) != 0 { opts << 'C' }

			mut i := ihl + 20
			for i < ihl + tcp_hdr_len && i < n {
				opt_kind := buf[i]
				if opt_kind == 0 { break }
				if opt_kind == 1 {
					i++
					continue
				}
				opt_len := buf[i+1]
				if opt_len < 2 { break }
				
				if opt_kind == 2 && opt_len == 4 {
					mss := int((u32(buf[i+2]) << 8) | u32(buf[i+3]))
					opts << 'M${mss}'
				} else if opt_kind == 3 && opt_len == 3 {
					opts << 'W${buf[i+2]}'
				} else if opt_kind == 4 {
					opts << 'S'
				} else if opt_kind == 8 && opt_len == 10 {
					opts << 'T'
					ts_val = (u32(buf[i+2]) << 24) | (u32(buf[i+3]) << 16) | (u32(buf[i+4]) << 8) | u32(buf[i+5])
				}
				i += opt_len
			}
			tcp_fp := if opts.len > 0 { opts.join('_') } else { 'NO_OPTS' }
			return ip_ttl, ip_tos, ip_df, win_size, tcp_fp, ts_val, ip_id
		}
	}
	return -1, -1, false, -1, 'TIMEOUT', 0, 0
}

fn check_dns_poisoning() bool {
	rand_val := time.ticks()
	fake_host := 'env-detect-${rand_val}.nonexistent'
	res := os.execute('ping -c 1 -W 1 ${fake_host}')
	if res.exit_code == 0 || res.output.contains('PING') {
		return true
	}
	return false
}

fn probe(host string, port int, resolved_ip string) !NetworkProfile {
	if resolved_ip == '' { return error('DNS resolution failed') }
	
	l3l4_thread := spawn capture_deep_packet_signature(resolved_ip, port)
	time.sleep(100 * time.millisecond)
	
	mut sw := time.new_stopwatch()
	mut conn := net.dial_tcp('${host}:${port}') or { return error('Connection refused or blocked') }
	rtt := sw.elapsed().milliseconds()
	conn.close() or {}
	
	ttl, tos, df, win_size, tcp_fingerprint, tsval, ip_id := l3l4_thread.wait()
	if ttl == -1 { return error('Layer 4 capture timeout') }
	deep_ja4s, cert_fp := get_deep_tls_fingerprint(host, port)
	
	mut pmtu := 1500
	if tcp_fingerprint.contains('M') {
		parts := tcp_fingerprint.split('M')
		if parts.len > 1 {
			val_str := parts[1].split('_')[0]
			mss := val_str.int()
			if mss > 0 {
				pmtu = mss + 40
			}
		}
	}
	
	dns_bad := check_dns_poisoning()
	
	return NetworkProfile{
		rtt: rtt
		ip_ttl: ttl
		ip_tos: tos
		ip_df: df
		ip_id: ip_id
		tcp_win: win_size
		tcp_opts: tcp_fingerprint
		tcp_tsval: tsval
		tls_ja4s: deep_ja4s
		tls_cert: cert_fp
		dns_bad: dns_bad
		pmtu: pmtu
	}
}

fn main() {
	if C.geteuid() != 0 {
		eprintln('[FATAL] Root privileges required for raw socket access.')
		eprintln('[FATAL] Please run the executable with sudo.')
		exit(1)
	}

	println('Network Anomaly Detection & Telemetry Probe')
	println('Version: 1.1.0-release')
	println('-------------------------------------------')

	mut target_host := 'google.com'
	target_port := 443
	if os.args.len > 1 { target_host = os.args[1] }

	resolved_ip := resolve_host(target_host)
	if resolved_ip == '' {
		eprintln('[FATAL] DNS resolution failed for target: ${target_host}')
		exit(1)
	}

	println('[INFO] Target mapping: ${target_host} -> ${resolved_ip}:${target_port}')
	println('[INFO] Initiating baseline calibration (5 cycles)...')
	
	mut allowed_ttls := []int{}
	mut allowed_toses := []int{}
	mut allowed_ip_ids := []u16{}
	mut f_win := 0
	mut f_df := false
	mut f_tcp_fp := ''
	mut f_ja4s := ''
	mut f_cert := ''
	mut f_pmtu := 0
	mut rtts := []i64{}

	for i in 0 .. 5 {
		fp := probe(target_host, target_port, resolved_ip) or {
			eprintln('[WARN] Cycle ${i+1} failed: ${err}')
			time.sleep(1 * time.second)
			continue
		}
		if fp.ip_ttl !in allowed_ttls { allowed_ttls << fp.ip_ttl }
		if fp.ip_tos !in allowed_toses { allowed_toses << fp.ip_tos }
		if fp.ip_id !in allowed_ip_ids { allowed_ip_ids << fp.ip_id }
		
		f_df = fp.ip_df
		f_win = fp.tcp_win
		f_tcp_fp = fp.tcp_opts
		f_ja4s = fp.tls_ja4s
		f_cert = fp.tls_cert
		f_pmtu = fp.pmtu
		rtts << fp.rtt
		
		println('       Cycle ${i+1}: RTT=${fp.rtt}ms TTL=${fp.ip_ttl} ToS=${fp.ip_tos} TSVal=${fp.tcp_tsval} ID=${fp.ip_id}')
		time.sleep(1 * time.second)
	}

	if allowed_ttls.len == 0 {
		eprintln('[FATAL] Baseline calibration failed. Network unreachable.')
		exit(1)
	}

	mut sum_rtt := i64(0)
	for r_val in rtts { sum_rtt += r_val }
	base_rtt := sum_rtt / i64(rtts.len)

	println('\n[INFO] Baseline profile established successfully:')
	println('       TTL Range:     ${allowed_ttls}')
	println('       ToS Tags:      ${allowed_toses}')
	println('       DF Flag:       ${f_df}')
	println('       IP ID Range:   ${allowed_ip_ids}')
	println('       TCP Window:    ${f_win}')
	println('       TCP Signature: ${f_tcp_fp}')
	println('       TLS Signature: ${f_ja4s}')
	println('       Cert Hash:     ${f_cert}')
	println('       Path MTU:      ${f_pmtu}')
	println('       Avg Latency:   ${base_rtt}ms\n')
	println('[INFO] Activating continuous monitoring protocol...\n')

	for {
		time.sleep(4 * time.second)
		
		curr := probe(target_host, target_port, resolved_ip) or {
			now := time.now().format_ss()
			println('[${now}] [WARN: PROBE DROPPED] Network connectivity loss or probe timeout.')
			continue 
		}
		
		mut score := 0
		mut reasons := []string{}
		
		mut is_ttl_ok := false
		for t in allowed_ttls {
			if math.abs(t - curr.ip_ttl) <= 2 {
				is_ttl_ok = true
				break
			}
		}
		if !is_ttl_ok {
			score += 10
			reasons << 'Routing Variance: TTL ${curr.ip_ttl} falls outside baseline ${allowed_ttls}'
		}

		if curr.ip_tos !in allowed_toses {
			if curr.ip_tos != 0 && curr.ip_tos != 128 {
				score += 5
				reasons << 'Traffic Shaping: ToS altered from ${allowed_toses} to ${curr.ip_tos}'
			}
		}

		if curr.ip_df != f_df {
			score += 8
			reasons << 'Encapsulation Anomaly: DF flag mutated (Expected: ${f_df}, Received: ${curr.ip_df})'
		}
		
		if curr.tcp_win != f_win && !curr.tcp_opts.contains('ERR_') {
			score += 4
			reasons << 'L4 Window Discrepancy: Mutated from ${f_win} to ${curr.tcp_win}'
		}

		if curr.tcp_opts != f_tcp_fp && !curr.tcp_opts.contains('ERR_') {
			score += 10
			reasons << 'Kernel Stack Modification: Expected [${f_tcp_fp}], Received [${curr.tcp_opts}]'
		}
		
		if curr.tls_ja4s != f_ja4s {
			score += 10
			reasons << 'Crypto Signature Mismatch: Expected [${f_ja4s}], Received [${curr.tls_ja4s}]'
		}

		if curr.tls_cert != f_cert && curr.tls_cert != 'NO_CERT' && f_cert != 'NO_CERT' {
			score += 15
			reasons << 'MITM SSL Decryption: Certificate modified to [${curr.tls_cert}]'
		}

		if curr.dns_bad {
			score += 15
			reasons << 'DNS Poisoning: Non-existent domain successfully resolved'
		}

		if curr.pmtu != f_pmtu {
			score += 8
			reasons << 'Path MTU Modification: Expected ${f_pmtu}, Received ${curr.pmtu}'
		}

		if allowed_ip_ids.len == 1 && allowed_ip_ids[0] == 0 && curr.ip_id != 0 {
			score += 7
			reasons << 'IP ID Zero-to-Value Anomaly: Static zero mutated to sequential/random ID: ${curr.ip_id}'
		}
		
		if base_rtt > 0 && curr.rtt > (base_rtt * 3) {
			score += 2
			reasons << 'Latency Spike Detected: ${curr.rtt}ms (Baseline: ${base_rtt}ms)'
		}

		now_str := time.now().format_ss()
		
		if score == 0 {
			println('[${now_str}] [STATUS: OK] RTT:${curr.rtt}ms TTL:${curr.ip_ttl} ToS:${curr.ip_tos} WIN:${curr.tcp_win}')
		} else if score >= 8 {
			println('\n[${now_str}] [ALERT: CRITICAL ANOMALY DETECTED]')
			println(' -> Profile Integrity Score: -${score}')
			for r in reasons {
				println(' -> ${r}')
			}
			println('--------------------------------------------------\n')
		} else {
			println('[${now_str}] [WARN: MINOR DEVIATION] Reason: ${reasons[0]}')
		}
	}
}
