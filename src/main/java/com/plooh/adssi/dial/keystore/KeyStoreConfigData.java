package com.plooh.adssi.dial.keystore;

import java.util.HashMap;
import java.util.Map;

import lombok.Getter;

@Getter
public class KeyStoreConfigData {
    private String filePath;
    private char[] storeSecret;
    private Map<String, char[]> keySecrets = new HashMap<>();

    public KeyStoreConfigData(String filePath, char[] storeSecret) {
        this.filePath = filePath;
        this.storeSecret = storeSecret;
    }

}