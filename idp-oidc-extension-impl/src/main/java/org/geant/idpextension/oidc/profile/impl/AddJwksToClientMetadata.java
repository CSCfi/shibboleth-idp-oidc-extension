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

package org.geant.idpextension.oidc.profile.impl;

import java.net.URI;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.client.HttpClient;
import org.geant.idpextension.oidc.metadata.support.RemoteJwkUtils;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that adds the jwks or jwks_uri to the client metadata, if one of those were defined in the request.
 * Both cannot be defined, as specified in https://openid.net/specs/openid-connect-registration-1_0.html section 2.
 */
public class AddJwksToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddJwksToClientMetadata.class);
    
    /** The {@link HttpClient} to use. */
    @NonnullAfterInit private HttpClient httpClient;
    
    /** HTTP client security parameters. */
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;
    
    /**
     * Constructor.
     */
    public AddJwksToClientMetadata() {
        super();
    }
    
    /**
     * Set the {@link HttpClient} to use.
     * 
     * @param client client to use
     */
    public void setHttpClient(@Nonnull final HttpClient client) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
    }

    /**
     * Set the optional client security parameters.
     * 
     * @param params the new client security parameters
     */
    public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClientSecurityParameters = params;
    }

    /** {@inheritDoc} */
    public void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (httpClient == null) {
            throw new ComponentInitializationException(getLogPrefix() + " HttpClient cannot be null");
        }
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
            final JWKSet remoteSet = RemoteJwkUtils.fetchRemoteJwkSet(getLogPrefix(), jwkUri, httpClient, 
                    httpClientSecurityParameters);
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
}
