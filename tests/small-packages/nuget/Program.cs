// Wycheproof ML-KEM vectors against KyberNET (NuGet package with its own implementation), through its public interface.
// Usage:  dotnet run -c Release -- <directory with mlkem_*.txt>
//
// Vector format (hex, fields separated by "|"), produced by mlkem_to_text.py:
//   D|tcId|result|seed d||z|ek|c|K|comment     generate the key from the seed and decapsulate c
//   E|tcId|result|m|ek|c|K|comment             encapsulate with ek and the randomness m
//   X|tcId|result|dk|c|K||comment              decapsulate with the expanded decapsulation key
//
// Return conventions, read in the package's source code:
//   KyberNET (github.com/MirceaMelinte/KyberNET): ML-KEM only.
//     There is no key generation from a seed, but KyberKeyGenerator.Generate(parameters, IRandomProvider) and
//     KyberEncapsulationKey.Encapsulate(IRandomProvider) take their randomness from a public interface: they are given a
//     provider that delivers the vector's bytes. Generate asks first for z (32 bytes) and then for d (32 bytes).
//     KyberEncapsulationKey.FromBytes(ek) / KyberDecapsulationKey.FromBytes(dk) / KyberCipherText.FromBytes(c) pick the
//     parameter set from the length and throw if they do not recognise it; FromBytes(dk) also checks the hash H(ek).
//     KyberDecapsulationKey.Decapsulate(c) -> K. The exceptions are InvalidKyberKeyException,
//     UnsupportedKyberVariantException and RandomBitGenerationException (if the randomness is all zeros).
//     If a FromBytes returns an object of ANOTHER parameter set (the length matches that of another set), the program
//     treats it as a rejection, which is what a caller would do, but records it separately ("other set").
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using KyberNET;
using KyberNET.Constants;
using KyberNET.Keys;

// Randomness provider that delivers, in order, the blocks it is given (public IRandomProvider interface of KyberNET).
sealed class FixedRandom : IRandomProvider
{
    readonly Queue<byte[]> blocks;
    public FixedRandom(params byte[][] b) { blocks = new Queue<byte[]>(b); }
    public void FillWithRandom(byte[] buffer)
    {
        var b = blocks.Dequeue();
        if (b.Length != buffer.Length) throw new InvalidOperationException($"fixed randomness: {buffer.Length} bytes requested, {b.Length} available");
        Buffer.BlockCopy(b, 0, buffer, 0, b.Length);
    }
}

// A fault of this program, not of the library: it does not count as a rejection.
sealed class OwnFault : Exception { public OwnFault(string m) : base(m) { } }

static class P
{
    static readonly string[] T = { "seed", "encaps", "expanded dk" };
    static byte[] H(string s) => Convert.FromHexString(s);
    static bool Same(byte[] a, byte[] b) => a != null && b != null && a.AsSpan().SequenceEqual(b);
    static string Version(Assembly a) => a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0]
                                         ?? a.GetName().Version.ToString();

    // Result of an operation: Ok = the library did it without error; whatever outputs there are.
    // None = the package has no public interface for that operation (counted neither as accepted nor as rejected).
    record Res(bool Ok, byte[] Ek = null, byte[] C = null, byte[] K = null, string Err = null, bool None = false);

    static Res Call(Func<Res> f)
    {
        try { return f(); }
        catch (OwnFault) { throw; }
        catch (InvalidOperationException e) when (e.Message.StartsWith("fixed randomness")) { throw; }
        catch (NullReferenceException) { throw; }      // not expected in this library; if it happens, let it show
        catch (Exception e) { return new Res(false, Err: e.GetType().Name); }
    }

    static void Main(string[] a)
    {
        if (a.Length < 1) { Console.WriteLine("Usage: dotnet run -c Release -- <vector directory>"); Environment.Exit(2); }
        string dir = a[0];
        foreach (var p in new[] { 512, 768, 1024 }) TestKem(new KyberNet(p), dir, p);
    }

    abstract class Adapter
    {
        public abstract string Name { get; }
        public abstract Res Seed(byte[] seed, byte[] c);
        public abstract Res Encaps(byte[] ek, byte[] m);
        public abstract Res DecapsDk(byte[] dk, byte[] c);
        public int OtherSet;       // times FromBytes returned another parameter set
    }

    sealed class KyberNet : Adapter
    {
        readonly KyberParameter par;
        public KyberNet(int p) { par = p == 512 ? KyberParameter.MlKem512 : p == 768 ? KyberParameter.MlKem768 : KyberParameter.MlKem1024; }
        public override string Name => "KyberNET " + Version(typeof(KyberKeyGenerator).Assembly);
        bool Mine(KyberParameter x) { if (x == par) return true; OtherSet++; return false; }
        public override Res Seed(byte[] seed, byte[] c)
        {
            // The interface only takes d and z of 32 bytes each: a seed of another length cannot even be passed.
            if (seed.Length != 64) return new Res(false, None: true);
            using var kp = KyberKeyGenerator.Generate(par, new FixedRandom(seed[32..], seed[..32]));   // first z, then d
            var ct = KyberCipherText.FromBytes(c);
            if (!Mine(ct.Parameter)) return new Res(false, Err: "c of another set");
            return new Res(true, Ek: kp.EncapsulationKey.FullBytes, K: kp.DecapsulationKey.Decapsulate(ct));
        }
        public override Res Encaps(byte[] ek, byte[] m)
        {
            var key = KyberEncapsulationKey.FromBytes(ek);
            if (!Mine(key.Parameter)) return new Res(false, Err: "ek of another set");
            using var r = key.Encapsulate(new FixedRandom(m));
            return new Res(true, C: r.CipherText.FullBytes, K: r.SharedSecretKey);
        }
        public override Res DecapsDk(byte[] dk, byte[] c)
        {
            using var key = KyberDecapsulationKey.FromBytes(dk);
            if (!Mine(key.Parameter)) return new Res(false, Err: "dk of another set");
            var ct = KyberCipherText.FromBytes(c);
            if (!Mine(ct.Parameter)) return new Res(false, Err: "c of another set");
            return new Res(true, K: key.Decapsulate(ct));
        }
    }

    static void TestKem(Adapter ad, string dir, int p)
    {
        int[] n = new int[3], acc = new int[3], fail = new int[3], none = new int[3];
        foreach (var line in File.ReadLines(Path.Combine(dir, $"mlkem_{p}.txt")))
        {
            var x = line.Split('|');
            if (x.Length < 8) continue;
            int t = "DEX".IndexOf(x[0][0]);
            bool valid = x[2] == "valid", good;
            Res r;
            if (t == 0)
            {
                r = Call(() => ad.Seed(H(x[3]), H(x[5])));
                good = r.Ok && Same(r.K, H(x[6])) && (x[4] == "" || Same(r.Ek, H(x[4])));
            }
            else if (t == 1)
            {
                r = Call(() => ad.Encaps(H(x[4]), H(x[3])));
                good = r.Ok && Same(r.C, H(x[5])) && Same(r.K, H(x[6]));
            }
            else
            {
                r = Call(() => ad.DecapsDk(H(x[3]), H(x[4])));
                good = r.Ok && Same(r.K, H(x[5]));
            }
            if (r.None) { none[t]++; continue; }
            n[t]++;
            if (valid && !good) { fail[t]++; Console.WriteLine($"  valid fails       [{T[t]}] tcId={x[1]} ({(r.Ok ? "different result" : "error " + r.Err)})  {x[7]}"); }
            if (!valid && r.Ok) { acc[t]++; Console.WriteLine($"  INVALID ACCEPTED  [{T[t]}] tcId={x[1]}  {x[7]}"); }
        }
        var s = $"{ad.Name,-30} ML-KEM-{p,-4}";
        for (int t = 0; t < 3; t++)
            s += $" | {T[t]}: {n[t]} vectors, INVALID ACCEPTED={acc[t]}, valid fails={fail[t]}" + (none[t] > 0 ? $" (no interface {none[t]})" : "");
        if (ad.OtherSet > 0) s += $" | (FromBytes returned another parameter set {ad.OtherSet} times; counted as rejections)";
        Console.WriteLine(s);
    }
}
