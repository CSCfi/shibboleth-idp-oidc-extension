/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.metadata.support;

import java.io.IOException;
import java.net.URI;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.util.EntityUtils;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.security.httpclient.HttpClientSecuritySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;

import net.minidev.json.JSONObject;

/**
 * Generic utility methods related to remote JWK sets.
 */
public class RemoteJwkUtils {
    
    /**
     * Constructor.
     */
    private RemoteJwkUtils() {
        // prevented
    }
    
    /**
     * Fetches the JWK set from the given URI using the given client and security parameters.
     * @param uri The endpoint for the JWK set.
     * @return The JWK set fetched from the endpoint, or null if it couldn't be fetched.
     */
    public static JWKSet fetchRemoteJwkSet(final String logPrefix, final URI uri, final HttpClient httpClient, 
            final HttpClientSecurityParameters httpClientSecurityParameters) {
        final Logger log = LoggerFactory.getLogger(RemoteJwkUtils.class);
        final HttpResponse response;
        try {
            final HttpUriRequest get = RequestBuilder.get().setUri(uri).build();
            final HttpClientContext clientContext = HttpClientContext.create();
            HttpClientSecuritySupport.marshalSecurityParameters(clientContext, httpClientSecurityParameters, true);
            HttpClientSecuritySupport.addDefaultTLSTrustEngineCriteria(clientContext, get);
            response = httpClient.execute(get, clientContext);
            HttpClientSecuritySupport.checkTLSCredentialEvaluated(clientContext, get.getURI().getScheme());
        } catch (IOException e) {
            log.error("{} Could not get the JWK contents from {}", logPrefix, uri, e);
            return null;
        }
        if (response == null) {
            log.error("{} Could not get the JWK contents from {}", logPrefix, uri);
            return null;
        }
        final String output;
        try {
            output = EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (ParseException | IOException e) {
            log.error("{} Could not parse the JWK contents from {}", logPrefix, uri);
            return null;
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        log.trace("{} Fetched the following response body: {}", logPrefix, output);
        final JWKSet jwkSet;
        try {
            final JSONObject json = JSONObjectUtils.parse(output);
            // The following check is needed to avoid NPE from Nimbus if keys claim not found
            if (JSONObjectUtils.getJSONArray(json, "keys") == null) {
                log.error("{} Could not find 'keys' array from the JSON from {}", logPrefix, uri);
                return null;
            }
            jwkSet = JWKSet.parse(json);
        } catch (java.text.ParseException e) {
            log.error("{} Could not parse the contents from {}", logPrefix, uri, e);
            return null;
        }
        return jwkSet;
    }

}
