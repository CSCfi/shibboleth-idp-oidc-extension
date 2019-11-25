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

package org.geant.idpextension.oidc.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Nonnull;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.annotation.constraint.Unmodifiable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Base class for OIDC protocol configuration, containing configuration bit for setting client authentication methods.
 */
public abstract class AbstractOIDCClientAuthenticableProfileConfiguration extends AbstractOIDCProfileConfiguration {

    /**
     * Constructor.
     *
     * @param profileId Unique profile identifier.
     */
    protected AbstractOIDCClientAuthenticableProfileConfiguration(String profileId) {
        super(profileId);
        tokenEndpointAuthMethods = new ArrayList<>();
        tokenEndpointAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.toString());
        tokenEndpointAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST.toString());
        tokenEndpointAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_JWT.toString());
        tokenEndpointAuthMethods.add(ClientAuthenticationMethod.PRIVATE_KEY_JWT.toString());
    }

    /** Enabled token endpoint authentication methods. */
    @Nonnull
    @NonnullElements
    private List<String> tokenEndpointAuthMethods;

    /**
     * Get the enabled token endpoint authentication methods.
     * 
     * @return The enabled token endpoint authentication methods.
     */
    @Nonnull
    @NonnullElements
    @NotLive
    @Unmodifiable
    public List<String> getTokenEndpointAuthMethods() {
        return tokenEndpointAuthMethods;
    }

    /**
     * Set the enabled token endpoint authentication methods.
     * 
     * @param methods What to set.
     */
    public void setTokenEndpointAuthMethods(@Nonnull @NonnullElements final Collection<String> methods) {
        Constraint.isNotNull(methods, "Collection of methods cannot be null");

        tokenEndpointAuthMethods = new ArrayList<>(StringSupport.normalizeStringCollection(methods));
    }

}
