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

package org.geant.idpextension.oidc.config.navigate;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;
import net.shibboleth.idp.relyingparty.RelyingPartyConfigurationResolver;

import org.geant.idpextension.oidc.profile.api.OIDCSecurityConfiguration;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.EncryptionConfiguration;

/**
 * A function that returns a {@link EncryptionConfiguration} list for request object decryption by way of various lookup
 * strategies.
 * 
 * <p>
 * If a specific setting is unavailable, a null value is returned.
 * </p>
 */
public class RequestObjectDecryptionConfigurationLookupFunction
        extends AbstractRelyingPartyLookupFunction<List<EncryptionConfiguration>> {

    /** A resolver for default security configurations. */
    @Nullable
    private RelyingPartyConfigurationResolver rpResolver;

    /**
     * Set the resolver for default security configurations.
     * 
     * @param resolver the resolver to use
     */
    public void setRelyingPartyConfigurationResolver(@Nullable final RelyingPartyConfigurationResolver resolver) {
        rpResolver = resolver;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
    @Override
    @Nullable
    public List<EncryptionConfiguration> apply(@Nullable final ProfileRequestContext input) {

        final List<EncryptionConfiguration> configs = new ArrayList<>();

        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null) {
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc.getSecurityConfiguration() instanceof OIDCSecurityConfiguration
                    && ((OIDCSecurityConfiguration) pc.getSecurityConfiguration())
                            .getRequestObjectDecryptionConfiguration() != null) {
                configs.add(((OIDCSecurityConfiguration) pc.getSecurityConfiguration())
                        .getRequestObjectDecryptionConfiguration());
            }
        }

        // Check for a per-profile default (relying party independent) config.
        if (input != null && rpResolver != null) {
            final SecurityConfiguration defaultConfig =
                    rpResolver.getDefaultSecurityConfiguration(input.getProfileId());
            if (defaultConfig instanceof OIDCSecurityConfiguration
                    && ((OIDCSecurityConfiguration) defaultConfig).getRequestObjectDecryptionConfiguration() != null) {
                configs.add(((OIDCSecurityConfiguration) defaultConfig).getRequestObjectDecryptionConfiguration());
            }
        }
        // TODO: Add Support for global default ?
        return configs;
    }

}