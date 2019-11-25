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

package org.geant.idpextension.oauth2.config;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.config.AbstractOIDCClientAuthenticableProfileConfiguration;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Profile configuration for the OAuth2 Token Revocation. The profile is required to define client authentication
 * methods.
 */
public class OAuth2TokenRevocationConfiguration extends AbstractOIDCClientAuthenticableProfileConfiguration {

    /** OAuth2 Token Revocation URI. */
    public static final String PROTOCOL_URI = "https://tools.ietf.org/html/rfc7009";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oauth2/revocation";

    /**
     * Constructor.
     */
    public OAuth2TokenRevocationConfiguration() {
        this(PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId Unique profile identifier.
     */
    public OAuth2TokenRevocationConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
    }

}
