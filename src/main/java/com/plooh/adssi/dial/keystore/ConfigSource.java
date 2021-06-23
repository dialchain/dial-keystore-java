package com.plooh.adssi.dial.keystore;

/**
 * Provides secrets needed to access keys
 */
public interface ConfigSource {

    char[] readStoreSecret(String storeAlias);

    char[] readKeySecret(String storeAlias, String keyAlias);

    String readFilePath(String storeAlias);
}