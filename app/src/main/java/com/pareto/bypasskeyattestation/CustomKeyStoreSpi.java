package com.pareto.bypasskeyattestation;

import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

public final class CustomKeyStoreSpi extends KeyStoreSpi {
    public static volatile KeyStoreSpi keyStoreSpi;

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        return keyStoreSpi.engineGetKey(alias, password);
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Log.d("Pareto/Debug","engineGetCertificateChain " + alias);
        String rootPath = "/data/adb/modules/bypassKeyAttestation/";
        for (StackTraceElement e : Thread.currentThread().getStackTrace()) {
            if (e.getClassName().toLowerCase(Locale.ROOT).contains("droidguard")) {
                throw new UnsupportedOperationException();
            }
        }

        ArrayList<Certificate> al = new ArrayList<Certificate>();

        Certificate[] chains =  keyStoreSpi.engineGetCertificateChain(alias);
        int count = 0;
        for(Certificate cert : chains){

            try {
                byte[] tmp0 = cert.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
            File file0 = new File(rootPath+String.valueOf(count)+".txt");
            try  {
//               FileOutputStream fop0 = new FileOutputStream(file0);
//
//               // if file doesn't exists, then create it
//                if (!file0.exists()) {
//                    file0.createNewFile();
//                }
//
//                fop0.write(tmp0);
//                fop0.flush();
//                fop0.close();

                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    InputStream is = new FileInputStream(file0);
                    Certificate certificate = cf.generateCertificate(is);
                    al.add(certificate);
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                }

            } catch (IOException e) {
                e.printStackTrace();
            }

            count = count + 1;
        }

        return chains;
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return keyStoreSpi.engineGetCertificate(alias);
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return keyStoreSpi.engineGetCreationDate(alias);
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        keyStoreSpi.engineSetKeyEntry(alias, key, password, chain);
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        keyStoreSpi.engineSetKeyEntry(alias, key, chain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        keyStoreSpi.engineSetCertificateEntry(alias, cert);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        keyStoreSpi.engineDeleteEntry(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return keyStoreSpi.engineAliases();
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return keyStoreSpi.engineContainsAlias(alias);
    }

    @Override
    public int engineSize() {
        return keyStoreSpi.engineSize();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return keyStoreSpi.engineIsKeyEntry(alias);
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return keyStoreSpi.engineIsCertificateEntry(alias);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return keyStoreSpi.engineGetCertificateAlias(cert);
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        keyStoreSpi.engineStore(stream, password);
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException {
        keyStoreSpi.engineLoad(stream, password);
    }
}
