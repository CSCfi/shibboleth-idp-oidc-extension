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
