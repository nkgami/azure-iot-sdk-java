/*
*  Copyright (c) Microsoft. All rights reserved.
*  Licensed under the MIT license. See LICENSE file in the project root for full license information.
*/

package com.microsoft.azure.sdk.iot.provisioning.security.hsm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PemUtilities
{
    public static PrivateKey parsePrivateKey(String privateKeyString) throws CertificateException
    {
        try
        {
            // Codes_SRS_PEMUTILITIES_34_001: [This function shall return a Private Key instance created by the provided PEM formatted privateKeyString.]
            Security.addProvider(new BouncyCastleProvider());
            PEMParser privateKeyParser = new PEMParser(new StringReader(privateKeyString));
            Object possiblePrivateKey = privateKeyParser.readObject();
            PEMKeyPair ukp = (PEMKeyPair) possiblePrivateKey;
            return getPrivateKey(ukp);
        }
        catch (Exception e)
        {
            // Codes_SRS_PEMUTILITIES_34_002: [If any exception is encountered while attempting to create the private key instance, this function shall throw a CertificateException.]
            throw new CertificateException(e);
        }
    }

    public static X509Certificate parsePublicKeyCertificate(String publicKeyCertificateString) throws CertificateException
    {
        try
        {
            // Codes_SRS_PEMUTILITIES_34_003: [This function shall return an X509Certificate instance created by the provided PEM formatted publicKeyCertificateString.]
            Security.addProvider(new BouncyCastleProvider());
            PemReader publicKeyCertificateReader = new PemReader(new StringReader(publicKeyCertificateString));
            PemObject possiblePublicKeyCertificate = publicKeyCertificateReader.readPemObject();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(possiblePublicKeyCertificate.getContent()));
        }
        catch (Exception e)
        {
            // Codes_SRS_PEMUTILITIES_34_004: [If any exception is encountered while attempting to create the public key certificate instance, this function shall throw a CertificateException.]
            throw new CertificateException(e);
        }
    }

    private static PrivateKey getPrivateKey(PEMKeyPair ukp) throws PEMException
    {
        return new JcaPEMKeyConverter().setProvider("BC").getKeyPair(ukp).getPrivate();
    }
}
