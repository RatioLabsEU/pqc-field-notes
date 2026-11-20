// Wycheproof vectors against ML-KEM and ML-DSA in the Zig standard library.
// The vectors are embedded at compile time (@embedFile), so as not to depend on the file API, which changes between
// versions.
// Usage:  copy mlkem_*.txt and mldsa_*.txt next to this file, write options.zig with
//         "pub const with_dsa = true;" (false for versions without ML-DSA) and build it as run.sh does.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
const std = @import("std");
const builtin = @import("builtin");
const options = @import("options");

fn unhex(buf: []u8, s: []const u8) ?[]u8 {
    if (s.len % 2 != 0 or s.len / 2 > buf.len) return null;
    return std.fmt.hexToBytes(buf, s) catch null;
}

fn kem(comptime K: type, comptime name: []const u8, comptime data: []const u8) void {
    var total = [_]u32{ 0, 0, 0 };
    var accepted = [_]u32{ 0, 0, 0 };
    var failed = [_]u32{ 0, 0, 0 };
    const KIND = [_][]const u8{ "seed", "encaps", "expanded dk" };
    var b1: [4000]u8 = undefined;
    var b2: [4000]u8 = undefined;
    var b3: [64]u8 = undefined;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        var x: [8][]const u8 = undefined;
        var n: usize = 0;
        var fields = std.mem.splitScalar(u8, line, '|');
        while (fields.next()) |c| {
            if (n < 8) {
                x[n] = c;
                n += 1;
            }
        }
        if (n < 8) continue;
        const t: usize = if (x[0][0] == 'D') 0 else if (x[0][0] == 'E') 1 else 2;
        const valid = std.mem.eql(u8, x[2], "valid");
        var ok = false;
        var good = false;
        switch (t) {
            0 => blk: {
                const seed = unhex(&b1, x[3]) orelse break :blk;
                const c = unhex(&b2, x[5]) orelse break :blk;
                const expected = unhex(&b3, x[6]) orelse break :blk;
                if (seed.len != K.seed_length or c.len != K.ciphertext_length) break :blk;
                const kp = K.KeyPair.generateDeterministic(seed[0..K.seed_length].*) catch break :blk;
                const secret = kp.secret_key.decaps(c[0..K.ciphertext_length]) catch break :blk;
                ok = true;
                good = std.mem.eql(u8, &secret, expected);
            },
            1 => blk: {
                const m = unhex(&b3, x[3]) orelse break :blk;
                const ek = unhex(&b1, x[4]) orelse break :blk;
                if (m.len != K.encaps_seed_length or ek.len != K.PublicKey.encoded_length) break :blk;
                const pk = K.PublicKey.fromBytes(ek[0..K.PublicKey.encoded_length]) catch break :blk;
                const e = pk.encapsDeterministic(m[0..K.encaps_seed_length]);
                ok = true;
                var cb: [4000]u8 = undefined;
                var kb: [64]u8 = undefined;
                const c = unhex(&cb, x[5]) orelse break :blk;
                const expected = unhex(&kb, x[6]) orelse break :blk;
                good = std.mem.eql(u8, &e.ciphertext, c) and std.mem.eql(u8, &e.shared_secret, expected);
            },
            else => blk: {
                const dk = unhex(&b1, x[3]) orelse break :blk;
                const c = unhex(&b2, x[4]) orelse break :blk;
                const expected = unhex(&b3, x[5]) orelse break :blk;
                if (dk.len != K.SecretKey.encoded_length or c.len != K.ciphertext_length) break :blk;
                const sk = K.SecretKey.fromBytes(dk[0..K.SecretKey.encoded_length]) catch break :blk;
                const secret = sk.decaps(c[0..K.ciphertext_length]) catch break :blk;
                ok = true;
                good = std.mem.eql(u8, &secret, expected);
            },
        }
        total[t] += 1;
        if (valid and !good) {
            failed[t] += 1;
            std.debug.print("  valid fails       [{s}] tcId={s} ({s})  {s}\n", .{ KIND[t], x[1], if (ok) "different result" else "error", x[7] });
        }
        if (!valid and ok) {
            accepted[t] += 1;
            std.debug.print("  INVALID ACCEPTED  [{s}] tcId={s}  {s}\n", .{ KIND[t], x[1], x[7] });
        }
    }
    std.debug.print("Zig std {s:<12} | seed: {d} accepted={d} failed={d} | encaps: {d} accepted={d} failed={d} | expanded dk: {d} accepted={d} failed={d}\n", .{
        name, total[0], accepted[0], failed[0], total[1], accepted[1], failed[1], total[2], accepted[2], failed[2],
    });
}

fn dsa(comptime D: type, comptime name: []const u8, comptime data: []const u8) void {
    var total: u32 = 0;
    var accepted: u32 = 0;
    var rejected: u32 = 0;
    var bpk: [3000]u8 = undefined;
    var bmsg: [20000]u8 = undefined;
    var bctx: [600]u8 = undefined;
    var bsig: [6000]u8 = undefined;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
        var x: [7][]const u8 = undefined;
        var n: usize = 0;
        var fields = std.mem.splitScalar(u8, line, '|');
        while (fields.next()) |c| {
            if (n < 7) {
                x[n] = c;
                n += 1;
            }
        }
        if (n < 7) continue;
        const valid = std.mem.eql(u8, x[1], "valid");
        var ok = false;
        blk: {
            const pkb = unhex(&bpk, x[2]) orelse break :blk;
            const msg = unhex(&bmsg, x[3]) orelse break :blk;
            const ctx = unhex(&bctx, x[4]) orelse break :blk;
            const sigb = unhex(&bsig, x[5]) orelse break :blk;
            if (pkb.len != D.PublicKey.encoded_length or sigb.len != D.Signature.encoded_length) break :blk;
            const pk = D.PublicKey.fromBytes(pkb[0..D.PublicKey.encoded_length].*) catch break :blk;
            const sig = D.Signature.fromBytes(sigb[0..D.Signature.encoded_length].*) catch break :blk;
            sig.verifyWithContext(msg, pk, ctx) catch break :blk; // no error = signature accepted
            ok = true;
        }
        total += 1;
        if (valid and !ok) {
            rejected += 1;
            std.debug.print("  valid rejected    tcId={s}  {s}\n", .{ x[0], x[6] });
        }
        if (!valid and ok) {
            accepted += 1;
            std.debug.print("  INVALID ACCEPTED  tcId={s}  {s}\n", .{ x[0], x[6] });
        }
    }
    std.debug.print("Zig std {s:<12} vectors={d}   INVALID ACCEPTED={d}   valid rejected={d}\n", .{ name, total, accepted, rejected });
}

pub fn main() void {
    std.debug.print("== Zig {s}, {s}, mode {s}\n", .{ builtin.zig_version_string, @tagName(builtin.cpu.arch), @tagName(builtin.mode) });
    const k = std.crypto.kem.ml_kem;
    kem(k.MLKem512, "ML-KEM-512", @embedFile("mlkem_512.txt"));
    kem(k.MLKem768, "ML-KEM-768", @embedFile("mlkem_768.txt"));
    kem(k.MLKem1024, "ML-KEM-1024", @embedFile("mlkem_1024.txt"));
    if (options.with_dsa) {
        const d = std.crypto.sign.mldsa;
        dsa(d.MLDSA44, "ML-DSA-44", @embedFile("mldsa_44.txt"));
        dsa(d.MLDSA65, "ML-DSA-65", @embedFile("mldsa_65.txt"));
        dsa(d.MLDSA87, "ML-DSA-87", @embedFile("mldsa_87.txt"));
    }
}
