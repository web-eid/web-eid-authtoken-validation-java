// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

package eu.webeid.security.validator.ocsp;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.operator.DigestCalculator;

import java.io.OutputStream;

/**
 * BouncyCastle's OCSPReqBuilder needs a DigestCalculator but BC doesn't
 * provide any public implementations of it, hence this implementation.
 */
public final class DigestCalculatorImpl implements DigestCalculator {

    private static final AlgorithmIdentifier SHA1 = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
    private static final AlgorithmIdentifier SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

    private final DigestOutputStream dos;
    private final AlgorithmIdentifier algId;


    public static DigestCalculator sha1() {
        return new DigestCalculatorImpl(new SHA1Digest(), SHA1);
    }

    public static DigestCalculator sha256() {
        return new DigestCalculatorImpl(new SHA256Digest(), SHA256);
    }

    private DigestCalculatorImpl(Digest digest, AlgorithmIdentifier algId) {
        this.dos = new DigestOutputStream(digest);
        this.algId = algId;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    @Override
    public OutputStream getOutputStream() {
        return dos;
    }

    @Override
    public byte[] getDigest() {
        return dos.getDigest();
    }
}
