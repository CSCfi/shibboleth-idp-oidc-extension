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