package com.pareto.bypasskeyattestation;

import java.security.Provider;

public final class CustomProvider extends Provider {

    CustomProvider(Provider provider) {
        super(provider.getName(), provider.getVersion(), provider.getInfo());
        putAll(provider);
        this.put("KeyStore.AndroidKeyStore", CustomKeyStoreSpi.class.getName());
    }

    @Override
    public synchronized Service getService(String type, String algorithm) {
        return super.getService(type, algorithm);
    }
}
