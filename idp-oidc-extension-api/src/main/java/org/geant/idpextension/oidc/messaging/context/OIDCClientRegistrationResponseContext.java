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

package org.geant.idpextension.oidc.messaging.context;

import org.joda.time.DateTime;
import org.opensaml.messaging.context.BaseContext;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Subcontext carrying information on OIDC client registration response. This
 * context appears as a subcontext of the {@link org.opensaml.messaging.context.MessageContext}.
 */
public class OIDCClientRegistrationResponseContext extends BaseContext  {

    /** Mandatory Unique Client Identifier. */
    private String clientId;
    
    /** Optional client secret. */
    private String clientSecret;
    
    /** Optional registration access token. */
    private String regAccessToken;
    
    /** Optional location of the client configuration endpoint. */
    private String regClientUri;
    
    /** Optional time at which the client identifier was issued. */
    private DateTime clientIdIssuedAt;
    
    /** Time at which the client secret will expire or 0 if it will not expire. Required if the secret was issued. */
    private DateTime clientSecretExpiresAt;
    
    /** The metadata for the client: the attributes supported by the OP must be included. */
    private OIDCClientMetadata clientMetadata;

    /**
     * Get the client identifier.
     * @return The client identifier.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Set the client identifier.
     * @param id The client identifier.
     */
    public void setClientId(final String id) {
        this.clientId = id;
    }

    /**
     * Get the client secret.
     * @return The client secret.
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Set the client secret.
     * @param secret The client secret.
     */
    public void setClientSecret(final String secret) {
        this.clientSecret = secret;
    }

    /**
     * Get the registration access token.
     * @return The registration access token.
     */
    public String getRegAccessToken() {
        return regAccessToken;
    }

    /**
     * Set the registration access token.
     * @param accessToken The registration access token.
     */
    public void setRegAccessToken(final String accessToken) {
        this.regAccessToken = accessToken;
    }

    /**
     * Get the location of the client configuration endpoint.
     * @return The location of the client configuration endpoint.
     */
    public String getRegClientUri() {
        return regClientUri;
    }

    /**
     * Set the location of the client configuration endpoint.
     * @param clientUri The location of the client configuration endpoint.
     */
    public void setRegClientUri(final String clientUri) {
        this.regClientUri = clientUri;
    }

    /**
     * Get the time at which the client identifier was issued.
     * @return The time at which the client identifier was issued.
     */
    public DateTime getClientIdIssuedAt() {
        return clientIdIssuedAt;
    }

    /**
     * Set the time at which the client identifier was issued.
     * @param idIssuedAt The time at which the client identifier was issued.
     */
    public void setClientIdIssuedAt(final DateTime idIssuedAt) {
        this.clientIdIssuedAt = idIssuedAt;
    }

    /**
     * Get the time at which the client secret will expire.
     * @return The time at which the client secret will expire.
     */
    public DateTime getClientSecretExpiresAt() {
        return clientSecretExpiresAt;
    }

    /**
     * Set the time at which the client secret will expire.
     * @param secretExpiresAt The time at which the client secret will expire.
     */
    public void setClientSecretExpiresAt(final DateTime secretExpiresAt) {
        this.clientSecretExpiresAt = secretExpiresAt;
    }

    /**
     * Get the metadata for the client: the attributes supported by the OP must be included.
     * @return The metadata for the client: the attributes supported by the OP must be included.
     */
    public OIDCClientMetadata getClientMetadata() {
        return clientMetadata;
    }
    
    /**
     * Set the metadata for the client: the attributes supported by the OP must be included.
     * @param metadata The metadata for the client: the attributes supported by the OP must be included.
     */
    public void setClientMetadata(final OIDCClientMetadata metadata) {
        this.clientMetadata = metadata;
    }
}