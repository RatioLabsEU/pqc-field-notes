// Wycheproof ML-KEM vectors against Bouncy Castle (Java, lightweight API).
// Usage:  java WycheproofMLKEM <directory with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//
// Line types as in mlkem_to_text.py: D = key from a 64-byte seed, then decapsulation (the shared secret is compared);
// E = encapsulation with the randomness m (ciphertext and shared secret are compared); X = decapsulation with an
// expanded decapsulation key. Any exception counts as a rejection.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class WycheproofMLKEM
{
    static void run(String name, String file, MLKEMParameters p) throws Exception
    {
        String[] kinds = {"seed", "encaps", "expanded dk"};
        int[] n = new int[3], accepted = new int[3], failed = new int[3];
        for (String line : Files.readAllLines(Paths.get(file)))
        {
            String[] x = line.split("\\|", 8);
            if (x.length < 8)
            {
                continue;
            }
            boolean expected = x[2].equals("valid");
            boolean ok = false, good = false;
            int t = x[0].equals("D") ? 0 : x[0].equals("E") ? 1 : 2;
            try
            {
                if (t == 0)
                {
                    byte[] seed = Hex.decode(x[3]);
                    if (seed.length == 64)
                    {
                        MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(p, seed);
                        byte[] K = new MLKEMExtractor(priv).extractSecret(Hex.decode(x[5]));
                        ok = true;
                        good = Arrays.equals(K, Hex.decode(x[6]));
                    }
                }
                else if (t == 1)
                {
                    byte[] m = Hex.decode(x[3]);
                    if (m.length == 32)
                    {
                        MLKEMPublicKeyParameters pub = new MLKEMPublicKeyParameters(p, Hex.decode(x[4]));
                        SecretWithEncapsulation s = new MLKEMGenerator(new java.security.SecureRandom()).internalGenerateEncapsulated(pub, m);
                        ok = true;
                        good = Arrays.equals(s.getEncapsulation(), Hex.decode(x[5])) && Arrays.equals(s.getSecret(), Hex.decode(x[6]));
                    }
                }
                else
                {
                    MLKEMPrivateKeyParameters priv = new MLKEMPrivateKeyParameters(p, Hex.decode(x[3]));
                    byte[] K = new MLKEMExtractor(priv).extractSecret(Hex.decode(x[4]));
                    ok = true;
                    good = Arrays.equals(K, Hex.decode(x[5]));
                }
            }
            catch (Throwable e)
            {
                ok = false;
            }
            n[t]++;
            if (expected && !good)
            {
                failed[t]++;
                System.out.println("  valid fails       [" + kinds[t] + "] tcId=" + x[1] + "  " + x[7]);
            }
            if (!expected && ok)
            {
                accepted[t]++;
                System.out.println("  INVALID ACCEPTED  [" + kinds[t] + "] tcId=" + x[1] + "  " + x[7]);
            }
        }
        StringBuilder sb = new StringBuilder(String.format("%-30s", name));
        for (int t = 0; t < 3; t++)
        {
            sb.append(" | ").append(kinds[t]).append(": ").append(n[t]).append(" vectors, INVALID ACCEPTED=").append(accepted[t]).append(", valid fails=").append(failed[t]);
        }
        System.out.println(sb);
    }

    public static void main(String[] a) throws Exception
    {
        run("Bouncy Castle ML-KEM-512", a[0] + "/mlkem_512.txt", MLKEMParameters.ml_kem_512);
        run("Bouncy Castle ML-KEM-768", a[0] + "/mlkem_768.txt", MLKEMParameters.ml_kem_768);
        run("Bouncy Castle ML-KEM-1024", a[0] + "/mlkem_1024.txt", MLKEMParameters.ml_kem_1024);
    }
}
