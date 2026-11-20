// Wycheproof ML-KEM and ML-DSA vectors against OpenJDK's own implementation (SUN/SunJCE providers), through the
// public API (KeyFactory, KEM, Signature). A single file: run it with  java WycheproofJDK.java <dir> [rounds]
//
// Limits of the API, which the test respects:
//  - ML-KEM: the encapsulation randomness cannot be fixed, so for the encapsulation vectors only acceptance of the
//    encapsulation key is checked. Decapsulation is compared with the expected shared secret.
//  - ML-DSA: only vectors with an empty context (the others are counted as "not applicable").
// "rounds" repeats the whole set so that the just-in-time compiler gets to use the accelerated paths.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import javax.crypto.KEM;

public class WycheproofJDK
{
    static byte[] h(String s) { return HexFormat.of().parseHex(s); }

    static byte[] tlv(int tag, byte[]... parts)
    {
        ByteArrayOutputStream c = new ByteArrayOutputStream();
        for (byte[] p : parts) c.writeBytes(p);
        byte[] v = c.toByteArray();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        if (v.length < 128) o.write(v.length);
        else if (v.length < 256) { o.write(0x81); o.write(v.length); }
        else { o.write(0x82); o.write(v.length >> 8); o.write(v.length & 0xff); }
        o.writeBytes(v);
        return o.toByteArray();
    }

    // 2.16.840.1.101.3.4.<arc>.<n>
    static byte[] alg(int arc, int n) { return tlv(0x30, tlv(0x06, new byte[] { 0x60, (byte)0x86, 0x48, 0x01, 0x65, 0x03, 0x04, (byte)arc, (byte)n })); }

    static PublicKey publicKey(String name, byte[] alg, byte[] pk) throws Exception
    {
        byte[] bits = new byte[pk.length + 1];
        System.arraycopy(pk, 0, bits, 1, pk.length);
        return KeyFactory.getInstance(name).generatePublic(new X509EncodedKeySpec(tlv(0x30, alg, tlv(0x03, bits))));
    }

    // The private key forms that the different versions have used: seed [0], expanded key in an OCTET STRING, or raw.
    static PrivateKey privateKey(String name, byte[] alg, byte[] content) throws Exception
    {
        return KeyFactory.getInstance(name).generatePrivate(
            new PKCS8EncodedKeySpec(tlv(0x30, new byte[] { 0x02, 0x01, 0x00 }, alg, tlv(0x04, content))));
    }

    public static void main(String[] a) throws Exception
    {
        String dir = a[0];
        int rounds = a.length > 1 ? Integer.parseInt(a[1]) : 1;
        System.out.println("== OpenJDK " + System.getProperty("java.runtime.version") + " (" + System.getProperty("java.vm.name") + ", "
            + System.getProperty("os.arch") + "), rounds=" + rounds);
        String[] T = { "seed", "encaps", "expanded dk" };
        int[][] kem = { { 512, 1 }, { 768, 2 }, { 1024, 3 } };
        for (int[] k : kem)
        {
            String name = "ML-KEM-" + k[0];
            byte[] alg = alg(4, k[1]);
            List<String> lines = Files.readAllLines(Paths.get(dir, "mlkem_" + k[0] + ".txt"));
            int[] tot = new int[3], acc = new int[3], fail = new int[3], none = new int[3];
            for (int v = 0; v < rounds; v++)
            {
                boolean last = v == rounds - 1;
                for (String line : lines)
                {
                    String[] x = line.split("\\|", -1);
                    if (x.length < 8) continue;
                    int t = x[0].equals("D") ? 0 : x[0].equals("E") ? 1 : 2;
                    boolean valid = x[2].equals("valid"), ok = false, good = false, iface = true;
                    try
                    {
                        if (t == 1)
                        {
                            PublicKey pub = publicKey(name, alg, h(x[4]));
                            KEM.Encapsulated e = KEM.getInstance("ML-KEM").newEncapsulator(pub).encapsulate();
                            ok = e.key() != null; good = ok;
                        }
                        else
                        {
                            byte[] key = h(x[3]), c = h(t == 0 ? x[5] : x[4]), expected = h(t == 0 ? x[6] : x[5]);
                            PrivateKey priv = null;
                            byte[][] forms = t == 0
                                ? new byte[][] { tlv(0x80, key), key }
                                : new byte[][] { tlv(0x04, key), key };
                            for (byte[] f : forms)
                            {
                                try { priv = privateKey(name, alg, f); break; } catch (Exception e) { /* try another form */ }
                            }
                            if (priv == null)
                            {
                                // With a seed: if the version does not take seeds, there is no interface. With an expanded key: it is a rejection.
                                if (t == 0 && key.length == 64) iface = false;
                            }
                            else
                            {
                                byte[] K = KEM.getInstance("ML-KEM").newDecapsulator(priv).decapsulate(c).getEncoded();
                                ok = true; good = Arrays.equals(K, expected);
                            }
                        }
                    }
                    catch (Exception e) { ok = false; }
                    if (!last) continue;
                    if (!iface) { none[t]++; continue; }
                    tot[t]++;
                    if (valid && !good) { fail[t]++; System.out.println("  valid fails       [" + T[t] + "] tcId=" + x[1] + " (" + (ok ? "different result" : "error") + ")  " + x[7]); }
                    if (!valid && ok) { acc[t]++; System.out.println("  INVALID ACCEPTED  [" + T[t] + "] tcId=" + x[1] + "  " + x[7]); }
                }
            }
            StringBuilder s = new StringBuilder(String.format("OpenJDK %-12s", name));
            for (int t = 0; t < 3; t++)
                s.append(" | ").append(T[t]).append(": ").append(tot[t] == 0 && none[t] > 0 ? "no interface"
                    : tot[t] + " accepted=" + acc[t] + " failed=" + fail[t] + (none[t] > 0 ? " (no interface " + none[t] + ")" : ""));
            System.out.println(s);
        }
        int[][] dsa = { { 44, 17 }, { 65, 18 }, { 87, 19 } };
        for (int[] d : dsa)
        {
            String name = "ML-DSA-" + d[0];
            byte[] alg = alg(3, d[1]);
            List<String> lines = Files.readAllLines(Paths.get(dir, "mldsa_" + d[0] + ".txt"));
            int tot = 0, acc = 0, rej = 0, na = 0;
            for (int v = 0; v < rounds; v++)
            {
                boolean last = v == rounds - 1;
                for (String line : lines)
                {
                    String[] x = line.split("\\|", -1);
                    if (x.length < 7) continue;
                    if (!x[4].isEmpty()) { if (last) na++; continue; }
                    boolean valid = x[1].equals("valid"), ok = false;
                    try
                    {
                        Signature s = Signature.getInstance("ML-DSA");
                        s.initVerify(publicKey(name, alg, h(x[2])));
                        s.update(h(x[3]));
                        ok = s.verify(h(x[5]));        // true = signature accepted
                    }
                    catch (Exception e) { ok = false; }
                    if (!last) continue;
                    tot++;
                    if (valid && !ok) { rej++; System.out.println("  valid rejected    tcId=" + x[0] + "  " + x[6]); }
                    if (!valid && ok) { acc++; System.out.println("  INVALID ACCEPTED  tcId=" + x[0] + "  " + x[6]); }
                }
            }
            System.out.println(String.format("OpenJDK %-12s vectors=%d (not applicable %d)   INVALID ACCEPTED=%d   valid rejected=%d", name, tot, na, acc, rej));
        }
    }
}
