package com.plooh.adssi.dial.keystore;

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;

@Getter
public class SimpleConfigSource implements ConfigSource {

    private Map<String, KeyStoreConfigData> configData = new HashMap<>();

    @Override
    public char[] readStoreSecret(String storeAlias) {
        return configData.get(storeAlias).getStoreSecret();
    }

    @Override
    public char[] readKeySecret(String storeAlias, String keyAlias) {
        return configData.get(storeAlias).getKeySecrets().get(keyAlias);
    }

    @Override
    public String readFilePath(String storeAlias) {
        return configData.get(storeAlias).getFilePath();
    }
}