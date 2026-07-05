package com.backend.devsecopsplatform_backend.service.defectdojo;

import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@Component
public class DefectDojoHttpClientFactory {

    private static final int CONNECT_TIMEOUT_SEC = 15;
    private static final int READ_TIMEOUT_SEC = 60;

    private volatile RestTemplate secureTemplate;
    private volatile RestTemplate insecureTemplate;

    public RestTemplate create(boolean insecureSsl) {
        if (insecureSsl) {
            if (insecureTemplate == null) {
                synchronized (this) {
                    if (insecureTemplate == null) {
                        insecureTemplate = buildTemplate(true);
                    }
                }
            }
            return insecureTemplate;
        }
        if (secureTemplate == null) {
            synchronized (this) {
                if (secureTemplate == null) {
                    secureTemplate = buildTemplate(false);
                }
            }
        }
        return secureTemplate;
    }

    private RestTemplate buildTemplate(boolean insecureSsl) {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(Timeout.ofSeconds(CONNECT_TIMEOUT_SEC))
                .setResponseTimeout(Timeout.ofSeconds(READ_TIMEOUT_SEC))
                .build();
        CloseableHttpClient httpClient = insecureSsl
                ? insecureHttpClient(requestConfig)
                : HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build();
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return new RestTemplate(factory);
    }

    private static CloseableHttpClient insecureHttpClient(RequestConfig requestConfig) {
        try {
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(null, TrustAllStrategy.INSTANCE)
                    .build();
            SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, (hostname, session) -> true);
            return HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig)
                    .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(csf)
                            .build())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Impossible d'initialiser SSL permissif DefectDojo", e);
        }
    }
}
