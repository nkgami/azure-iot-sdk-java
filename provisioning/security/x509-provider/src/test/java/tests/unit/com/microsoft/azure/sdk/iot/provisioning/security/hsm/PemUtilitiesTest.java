/*
*  Copyright (c) Microsoft. All rights reserved.
*  Licensed under the MIT license. See LICENSE file in the project root for full license information.
*/

package tests.unit.com.microsoft.azure.sdk.iot.provisioning.security.hsm;

import com.microsoft.azure.sdk.iot.provisioning.security.hsm.PemUtilities;
import mockit.Deencapsulation;
import mockit.Mocked;
import mockit.NonStrictExpectations;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class PemUtilitiesTest
{
    private static final String expectedPrivateKeyString = "some private key string";
    private static final String expectedPublicKeyCertificateString = "some public key certificate string";

    @Mocked
    PrivateKey mockPrivateKey;
    @Mocked
    X509Certificate mockX509Certificate;
    @Mocked
    PEMKeyPair mockPEMKeyPair;
    @Mocked
    PEMParser mockPEMParser;
    @Mocked
    PemObject mockPemObject;
    @Mocked
    PemReader mockPemReader;
    @Mocked
    StringReader mockStringReader;
    @Mocked
    KeyPair mockKeyPair;
    @Mocked
    CertificateFactory mockCertificateFactory;

    // Tests_SRS_PEMUTILITIES_34_001: [This function shall return a Private Key instance created by the provided PEM formatted privateKeyString.]
    @Test
    public void parsePrivateKeySuccess() throws CertificateException, IOException
    {
        //arrange
        final PemUtilities pemUtilities = new PemUtilities();
        new NonStrictExpectations(pemUtilities)
        {
            {
                new StringReader(expectedPrivateKeyString);
                result = mockStringReader;

                new PEMParser(mockStringReader);
                result = mockPEMParser;

                mockPEMParser.readObject();
                result = mockPEMKeyPair;

                //Doing this instead of just mocking JCA converter because trying to mock the JCA converter causes strange errors to be thrown.
                Deencapsulation.invoke(pemUtilities, "getPrivateKey", new Class[] {PEMKeyPair.class}, mockPEMKeyPair);
                result = mockPrivateKey;
            }
        };

        //act
        PrivateKey actualPrivateKey = PemUtilities.parsePrivateKey(expectedPrivateKeyString);

        //assert
        assertEquals(mockPrivateKey, actualPrivateKey);
    }

    // Tests_SRS_PEMUTILITIES_34_002: [If any exception is encountered while attempting to create the private key instance, this function shall throw a CertificateException.]
    @Test (expected = CertificateException.class)
    public void parsePrivateKeyExceptionsWrappedInCertificateException() throws CertificateException, IOException
    {
        //arrange
        final PemUtilities pemUtilities = new PemUtilities();
        new NonStrictExpectations(pemUtilities)
        {
            {
                new StringReader(expectedPrivateKeyString);
                result = new IOException();
            }
        };

        //act
        PrivateKey actualPrivateKey = PemUtilities.parsePrivateKey(expectedPrivateKeyString);
    }

    // Tests_SRS_PEMUTILITIES_34_003: [This function shall return an X509Certificate instance created by the provided PEM formatted publicKeyCertificateString.]
    @Test
    public void parsePublicKeyCertificateSuccess() throws CertificateException, IOException
    {
        //arrange
        new NonStrictExpectations()
        {
            {
                new PemReader(new StringReader(expectedPublicKeyCertificateString));
                result = mockPemReader;

                mockPemReader.readPemObject();
                result = mockPemObject;

                CertificateFactory.getInstance("X.509");
                result = mockCertificateFactory;

                mockCertificateFactory.generateCertificate(new ByteArrayInputStream(mockPemObject.getContent()));
                result = mockX509Certificate;
            }
        };

        //act
        X509Certificate actualPublicKeyCertificate = PemUtilities.parsePublicKeyCertificate(expectedPublicKeyCertificateString);

        //assert
        assertEquals(mockX509Certificate, actualPublicKeyCertificate);
    }

    // Tests_SRS_PEMUTILITIES_34_004: [If any exception is encountered while attempting to create the public key certificate instance, this function shall throw a CertificateException.]
    @Test (expected = CertificateException.class)
    public void parsePublicKeyCertificateExceptionsWrappedInCertificateException() throws CertificateException, IOException
    {
        //arrange
        new NonStrictExpectations()
        {
            {
                new PemReader(new StringReader(expectedPublicKeyCertificateString));
                result = new IOException();
            }
        };

        //act
        X509Certificate actualPublicKeyCertificate = PemUtilities.parsePublicKeyCertificate(expectedPublicKeyCertificateString);

        //assert
        assertEquals(mockX509Certificate, actualPublicKeyCertificate);
    }
}
