package com.plooh.adssi.dial.keystore;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleProviderInstance {
    public static final BouncyCastleProvider BC = new BouncyCastleProvider();

    static {
        Security.addProvider(BC);
    }

    public static void init() {
    }
}