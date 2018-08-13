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

package org.geant.idpextension.oidc.profile.impl;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.util.EntityUtils;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that adds the jwks or jwks_uri to the client metadata, if one of those were defined in the request.
 * Both cannot be defined, as specified in https://openid.net/specs/openid-connect-registration-1_0.html section 2.
 */
public class AddJwksToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddJwksToClientMetadata.class);
    
    /** The builder for the {@link HttpClient}s. */
    private HttpClientBuilder clientBuilder;
    
    /**
     * Constructor.
     */
    public AddJwksToClientMetadata() {
        super();
        clientBuilder = new HttpClientBuilder();
    }
    
    /**
     * Set the builder for the {@link HttpClient}s.
     * @param builder The builder for the {@link HttpClient}s.
     */
    public void setHttpClientBuilder(final HttpClientBuilder builder) {
        clientBuilder = Constraint.isNotNull(builder, "The HttpClientBuilder cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final JWKSet jwkSet = getInputMetadata().getJWKSet();
        final URI jwkUri = getInputMetadata().getJWKSetURI();
        
        if (jwkSet != null && jwkUri != null) {
            log.warn("{} Both jwks and jwks_uri were defined", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        
        if (jwkSet != null) {
            if (containsKeys(jwkSet)) {
                getOutputMetadata().setJWKSet(jwkSet);
            } else {
                log.warn("{} The jwks was defined, but it doesn't contain any keys", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            }
            return;                
        }
        
        if (jwkUri != null) {
            final JWKSet remoteSet = fetchRemoteJwkSet(jwkUri);
            if (containsKeys(remoteSet)) {
                log.debug("{} The jwks_uri endpoint available and contains key(s)", getLogPrefix());
                getOutputMetadata().setJWKSetURI(jwkUri);
            } else {
                log.warn("{} The jwks_uri was defined, but the endpoint does not contain key(s)", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);                
            }
            return;
        }
    }
    
    /**
     * Checks that the given JWK set contains at least one key.
     * @param jwkSet The set of JWKs.
     * @return True if the set contains at least one key, false otherwise.
     */
    protected boolean containsKeys(final JWKSet jwkSet) {
        if (jwkSet == null) {
            return false;
        }
        final List<JWK> keys = jwkSet.getKeys();
        if (keys == null || keys.isEmpty()) {
            return false;
        }
        return true;
    }
    
    /**
     * Fetches the JWK set from the given URI using a client built with the attached {@link HttpClientBuilder}.
     * @param uri The endpoint for the JWK set.
     * @return The JWK set fetched from the endpoint, or null if it couldn't be fetched.
     */
    protected JWKSet fetchRemoteJwkSet(final URI uri) {
        final HttpResponse response;
        try {
            final HttpUriRequest get = RequestBuilder.get().setUri(uri).build();
            response = clientBuilder.buildClient().execute(get);
        } catch (Exception e) {
            log.error("{} Could not get the JWK contents from {}", getLogPrefix(), uri, e);
            return null;
        }
        if (response == null) {
            log.error("{} Could not get the JWK contents from {}", getLogPrefix(), uri);
            return null;
        }
        final String output;
        try {
            output = EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (ParseException | IOException e) {
            log.error("{} Could not parse the JWK contents from {}", getLogPrefix(), uri);
            return null;
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        log.trace("{} Fetched the following response body: {}", getLogPrefix(), output);
        final JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(output);
        } catch (java.text.ParseException e) {
            log.error("{} Could not parse the contents from {}", getLogPrefix(), uri, e);
            return null;
        }
        return jwkSet;
    }
}
