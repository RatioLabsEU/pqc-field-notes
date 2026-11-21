// Wycheproof ML-DSA verification vectors against Bouncy Castle (Java, lightweight API).
// Usage:  java WycheproofMLDSA <directory with mldsa_44.txt, mldsa_65.txt, mldsa_87.txt>
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.util.encoders.Hex;

public class WycheproofMLDSA
{
    // Any exception (malformed key, context too long, ...) counts as a rejection.
    static boolean verify(MLDSAParameters p, byte[] pk, byte[] msg, byte[] ctx, byte[] sig)
    {
        try
        {
            MLDSAPublicKeyParameters pub = new MLDSAPublicKeyParameters(p, pk);
            CipherParameters par = ctx.length > 0 ? new ParametersWithContext(pub, ctx) : pub;
            MLDSASigner s = new MLDSASigner();
            s.init(false, par);
            s.update(msg, 0, msg.length);
            return s.verifySignature(sig);
        }
        catch (Throwable e)
        {
            return false;
        }
    }

    static boolean run(String name, String file, MLDSAParameters p) throws Exception
    {
        int total = 0, badAccepted = 0, badRejected = 0;
        for (String line : Files.readAllLines(Paths.get(file)))
        {
            String[] c = line.split("\\|", 7);
            if (c.length < 7)
            {
                continue;
            }
            total++;
            boolean expected = c[1].equals("valid");
            boolean ok = verify(p, Hex.decode(c[2]), Hex.decode(c[3]), Hex.decode(c[4]), Hex.decode(c[5]));
            if (ok && !expected)
            {
                badAccepted++;
                System.out.println("  INVALID ACCEPTED  tcId=" + c[0] + "  " + c[6]);
            }
            if (!ok && expected)
            {
                badRejected++;
                System.out.println("  valid rejected    tcId=" + c[0] + "  " + c[6]);
            }
        }
        System.out.printf("%-34s vectors=%d   INVALID ACCEPTED=%d   valid rejected=%d%n", name, total, badAccepted, badRejected);
        return badAccepted == 0 && badRejected == 0;
    }

    public static void main(String[] a) throws Exception
    {
        boolean good = true;
        good &= run("Bouncy Castle ML-DSA-44", a[0] + "/mldsa_44.txt", MLDSAParameters.ml_dsa_44);
        good &= run("Bouncy Castle ML-DSA-65", a[0] + "/mldsa_65.txt", MLDSAParameters.ml_dsa_65);
        good &= run("Bouncy Castle ML-DSA-87", a[0] + "/mldsa_87.txt", MLDSAParameters.ml_dsa_87);
        System.exit(good ? 0 : 1);
    }
}
