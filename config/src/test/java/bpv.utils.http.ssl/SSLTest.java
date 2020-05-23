package bpv.utils.http.ssl;

import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;

import static junit.framework.TestCase.assertEquals;

public class SSLTest {

    private final String CLIENT_KEYSTORE_PATH = "target/client-truststore.jks";
    private final String CLIENT_KEYSTORE_PASS = "C1!entP@55w0rd";
    private final String BADSSL_KEY_PASS = "badssl.com";

    private final String SERVER_KEYSTORE_PATH = "target/server-truststore.jks";
    private final String SERVER_KEYSTORE_PASS = "5erverP@55w0rd";

    @Test
    public void testSSLConnection() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {

        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(readKeyStore(SERVER_KEYSTORE_PATH, SERVER_KEYSTORE_PASS), null)
                .build();

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2", "TLSv1.1"},
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());


        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();
        HttpGet httpGet = new HttpGet("https://stackoverflow.com/");
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, httpResponse.getStatusLine().getStatusCode());
    }

    @Test
    public void testSSLConnectionWithClientCert() throws IOException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException, CertificateException {

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(readKeyStore(CLIENT_KEYSTORE_PATH, CLIENT_KEYSTORE_PASS), BADSSL_KEY_PASS.toCharArray())
                .loadTrustMaterial(readKeyStore(SERVER_KEYSTORE_PATH, SERVER_KEYSTORE_PASS), null)
                .build();

        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2", "TLSv1.1"},
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());


        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslSocketFactory).build();
        HttpGet httpGet = new HttpGet("https://client.badssl.com/");
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, httpResponse.getStatusLine().getStatusCode());
    }

    private KeyStore readKeyStore(String filePath, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        try (InputStream keyStoreStream = new FileInputStream(new File(filePath))) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, password.toCharArray());
            return keyStore;
        }
    }
}
