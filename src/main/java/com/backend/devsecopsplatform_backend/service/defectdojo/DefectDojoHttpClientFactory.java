package com.backend.devsecopsplatform_backend.service.defectdojo;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;

@Component
public class DefectDojoHttpClientFactory {

    public RestTemplate create(boolean insecureSsl) {
        if (!insecureSsl) {
            return new RestTemplate();
        }
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                if (connection instanceof HttpsURLConnection https) {
                    https.setSSLSocketFactory(trustAllSslContext().getSocketFactory());
                    https.setHostnameVerifier(trustAllHostnameVerifier());
                }
                super.prepareConnection(connection, httpMethod);
            }
        };
        return new RestTemplate(factory);
    }

    private static SSLContext trustAllSslContext() {
        try {
            TrustManager[] trustAll = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("Impossible d'initialiser SSL permissif DefectDojo", e);
        }
    }

    private static HostnameVerifier trustAllHostnameVerifier() {
        return (hostname, session) -> true;
    }
}
