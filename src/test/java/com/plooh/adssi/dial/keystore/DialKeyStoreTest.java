package com.plooh.adssi.dial.keystore;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class DialKeyStoreTest {
    static String test_data_dir = "target/DialKeyStoreTest";
    static String keystorePath_testRead = test_data_dir + "/testRead/sampleKeyStore.uber";
    static String keystorePath_testWrite = test_data_dir + "/testWrite/sampleKeyStore.uber";

    @BeforeAll
    public static void setup() {
        BouncyCastleProviderInstance.init();
    }

    @AfterAll
    public static void cleanup() throws IOException {
        FileUtils.deleteDirectory(new File(test_data_dir));
    }

    @Test
    void testRead() throws IOException {
        String storeAlias = "sampleKeyStore";
        String keyAlias = "sampleKey";
        InputStream stream = DialKeyStoreTest.class.getResourceAsStream("/keystores/sampleKeyStore.uber");
        FileUtils.copyInputStreamToFile(stream, new File(keystorePath_testRead));
        stream.close();
        SimpleConfigSource secretSource = new SimpleConfigSource();
        KeyStoreConfigData keyStoreConfigData = new KeyStoreConfigData(keystorePath_testRead,
                "simple store password".toCharArray());
        secretSource.getConfigData().put(storeAlias, keyStoreConfigData);
        DialKeyStore dialKeyStore2 = new DialKeyStore(secretSource, storeAlias);
        Key key = dialKeyStore2.read(keyAlias);
        assertNotNull(key);
    }

    @Test
    void testWrite() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, OperatorCreationException,
            CertificateException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair keypair = g.generateKeyPair();
        PrivateKey privateKey = keypair.getPrivate();

        String storeAlias = "sampleKeyStore";
        String keyAlias = "sampleKey";
        SimpleConfigSource secretSource = new SimpleConfigSource();
        KeyStoreConfigData keyStoreConfigData = new KeyStoreConfigData(keystorePath_testWrite,
                "simple store password".toCharArray());
        secretSource.getConfigData().put(storeAlias, keyStoreConfigData);
        DialKeyStore dialKeyStore1 = new DialKeyStore(secretSource, storeAlias);

        X500Name owner = new X500Name("CN=" + keyAlias);
        final Date start = new Date();
        final Date until = Date
                .from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(owner,
                new BigInteger(10, new SecureRandom()), start, until, owner, keypair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(BouncyCastleProviderInstance.BC).build(keypair.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);

        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProviderInstance.BC)
                .getCertificate(holder);
        X509Certificate[] chain = new X509Certificate[1];

        chain[0] = cert;

        dialKeyStore1.write(keyAlias, privateKey, chain);

        DialKeyStore dialKeyStore2 = new DialKeyStore(secretSource, storeAlias);
        Key key = dialKeyStore2.read(keyAlias);
        assertNotNull(key);
    }
}
