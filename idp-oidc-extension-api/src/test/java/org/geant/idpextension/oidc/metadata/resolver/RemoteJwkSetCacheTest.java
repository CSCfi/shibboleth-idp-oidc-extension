/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.metadata.resolver;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HttpContext;
import org.mockito.Mockito;
import org.opensaml.core.config.InitializationException;
import org.opensaml.storage.StorageService;
import org.opensaml.storage.impl.MemoryStorageService;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jose.jwk.JWKSet;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link RemoteJwkSetCache}.
 */
public class RemoteJwkSetCacheTest {
    
    RemoteJwkSetCache jwkSetCache;
    StorageService storageService;
    HttpClient httpClient;
    
    
    @BeforeMethod
    public void setup() throws InitializationException, ComponentInitializationException {
        jwkSetCache = new RemoteJwkSetCache();
        storageService = buildStorageService();
    }
    
    protected StorageService buildStorageService() throws ComponentInitializationException {
        MemoryStorageService storageService = new MemoryStorageService();
        storageService.setId("mockId");
        storageService.initialize();
        return storageService;
    }
    
    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoHttpClient() throws ComponentInitializationException {
        jwkSetCache.setStorage(storageService);
        jwkSetCache.initialize();
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoStorageService() throws ComponentInitializationException {
        jwkSetCache.setHttpClient(HttpClientBuilder.create().build());
        jwkSetCache.initialize();
    }
    
    @Test
    public void testSuccessNoSecurity() throws ClientProtocolException, IOException, ComponentInitializationException,
            URISyntaxException, InterruptedException {
        jwkSetCache.setStorage(storageService);
        jwkSetCache.setHttpClient(createMockHttpClient(validJwkSet()));
        jwkSetCache.setHttpClientSecurityParameters(null);
        jwkSetCache.initialize();
        String uri = "http://example.org";
        System.out.println(new URI(uri).toString());
        JWKSet jwkSet = jwkSetCache.fetch(new URI(uri), System.currentTimeMillis() + 100);
        Assert.assertNotNull(jwkSet);
        Assert.assertNotNull(jwkSetCache.getStorage().read(RemoteJwkSetCache.CONTEXT_NAME, uri));
        jwkSet = jwkSetCache.fetch(new URI(uri), System.currentTimeMillis() + 100);
        Assert.assertNotNull(jwkSet);
        Thread.sleep(101);
        Assert.assertNull(storageService.read(RemoteJwkSetCache.CONTEXT_NAME, uri));
    }

    @Test
    public void testInvalidJwk() throws ClientProtocolException, IOException, ComponentInitializationException,
            URISyntaxException {
        jwkSetCache.setStorage(storageService);
        jwkSetCache.setHttpClient(createMockHttpClient("not_jwk_set"));
        jwkSetCache.initialize();
        JWKSet jwkSet = jwkSetCache.fetch(new URI("http://example.org"), (long) 100);
        Assert.assertNull(jwkSet);
    }

    protected HttpClient createMockHttpClient(String output) throws ClientProtocolException, IOException {
        HttpClient httpClient = Mockito.mock(HttpClient.class);
        HttpResponse httpResponse = Mockito.mock(HttpResponse.class);
        Mockito.when(httpResponse.getEntity()).thenReturn(new StringEntity(output));
        Mockito.when(httpClient.execute((HttpUriRequest) Mockito.any(), 
                (HttpContext) Mockito.any())).thenReturn(httpResponse);
        return httpClient;
    }
    
    protected String validJwkSet() {
        return "{\n" + 
                "  \"keys\": [\n" + 
                "    {\n" + 
                "      \"kid\": \"08d3245c62f86b6362afcbbffe1d069826dd1dc1\",\n" + 
                "      \"e\": \"AQAB\",\n" + 
                "      \"kty\": \"RSA\",\n" + 
                "      \"alg\": \"RS256\",\n" + 
                "      \"n\": \"mSLCSG1hK28xrzcSfgbvRinkIRjecBlwsQggynHppHiiT6I80waivIqTJBSFYyVuRCAHXi6apSsL5FUWKd42GOhVUayIyzvuz1CqTuh5a9ACXaJjEVLUFO39QfXxWrxhpSJCTN9aMkdtoV1QJqfAd3IF9MYwfojsoEn3d5XX5TX4RxqZ9-HGbgSLsRuAzFIg9NxxfTYhbECBskhhR4RIcam-1T52FafmK2LMiuIEDPiVg6LvAqWi8gdMRd8WhiP_ZIRJTCH4C0NFKmw1PZyKadVxvwg97vwPTF8qkFdwJ_kjQAMmq77PxankluAkfWjFqbD4JepO4HH3aJvU8Sl_Ow\",\n" + 
                "      \"use\": \"sig\"\n" + 
                "    },\n" + 
                "    {\n" + 
                "      \"alg\": \"RS256\",\n" + 
                "      \"n\": \"uS9Iep_r83oLpfnMXLnB5a8IVUP7ZRreM1rxNWYnaqEQr1NfRisyIi4cYG7KbWiuLCmRQOD7ybhpdHCcN9ty5evz4irWT5hIa98Jr3a2BISTskBbPmBgUR3_TuQ_fvxeQYCCETJUcho5gXK-yeDWJwcD2iwqpVzIZHz8BBe5AYFUlJMzwgzYMe9aqoOEWVv__Gd7Z_kaz5pa0lOsWUUPNFmeW4e4rtNvosx7ItyyyghIyG2KX-0phOgbfzG6Ub6qA9upBYK9KBtjcoe1ciV-Yn_3HaS5PlugYTo1zYnng1mW7UP5A_QT_HgDqD1clcz0WIEL6usVMRay87ECEmOhrw\",\n" + 
                "      \"use\": \"sig\",\n" + 
                "      \"kid\": \"b15a2b8f7a6b3f6bc08bc1c56a88410e146d01fd\",\n" + 
                "      \"e\": \"AQAB\",\n" + 
                "      \"kty\": \"RSA\"\n" + 
                "    }\n" + 
                "  ]\n" + 
                "}";
    }

}
