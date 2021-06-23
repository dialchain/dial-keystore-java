package com.plooh.adssi.dial.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class DialKeyStore {
    private KeyStore keyStore;
    private ConfigSource secretSource;
    private String storeAlias;

    public DialKeyStore(ConfigSource secretSource, String storeAlias) {
        this.secretSource = secretSource;
        this.storeAlias = storeAlias;
        try {
            loadKeystore();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public Key read(String keyId) {
        try {
            return keyStore.getKey(keyId, secretSource.readKeySecret(storeAlias, keyId));
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public void write(String keyId, Key key, X509Certificate[] certs) {
        try {
            keyStore.setKeyEntry(keyId, key, secretSource.readKeySecret(storeAlias, keyId), certs);
            FileOutputStream fos = new FileOutputStream(secretSource.readFilePath(storeAlias));
            keyStore.store(fos, secretSource.readStoreSecret(storeAlias));
            fos.close();
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void loadKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (keyStore != null)
            return;
        String filePath = secretSource.readFilePath(storeAlias);
        File file = new File(filePath);
        keyStore = KeyStore.getInstance("UBER");
        if (!file.exists()) {
            file.getParentFile().mkdirs();
            keyStore.load(null, null);
        } else {
            FileInputStream fis = new FileInputStream(file);
            keyStore.load(fis, secretSource.readStoreSecret(storeAlias));
            fis.close();
        }
    }
}