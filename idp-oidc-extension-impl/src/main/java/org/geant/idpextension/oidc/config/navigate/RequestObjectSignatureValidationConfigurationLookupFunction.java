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
import org.opensaml.xmlsec.SignatureSigningConfiguration;

/**
 * A function that returns a {@link SignatureSigningConfiguration} list for request object signature validation by way
 * of various lookup strategies.
 * 
 * <p>
 * If a specific setting is unavailable, a null value is returned.
 * </p>
 */
public class RequestObjectSignatureValidationConfigurationLookupFunction
        extends AbstractRelyingPartyLookupFunction<List<SignatureSigningConfiguration>> {

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
    public List<SignatureSigningConfiguration> apply(@Nullable final ProfileRequestContext input) {

        final List<SignatureSigningConfiguration> configs = new ArrayList<>();

        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null) {
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc.getSecurityConfiguration() instanceof OIDCSecurityConfiguration
                    && ((OIDCSecurityConfiguration) pc.getSecurityConfiguration())
                            .getRequestObjectDecryptionConfiguration() != null) {
                configs.add(((OIDCSecurityConfiguration) pc.getSecurityConfiguration())
                        .getRequestObjectSignatureValidationConfiguration());
            }
        }

        // Check for a per-profile default (relying party independent) config.
        if (input != null && rpResolver != null) {
            final SecurityConfiguration defaultConfig =
                    rpResolver.getDefaultSecurityConfiguration(input.getProfileId());
            if (defaultConfig instanceof OIDCSecurityConfiguration
                    && ((OIDCSecurityConfiguration) defaultConfig).getRequestObjectDecryptionConfiguration() != null) {
                configs.add(
                        ((OIDCSecurityConfiguration) defaultConfig).getRequestObjectSignatureValidationConfiguration());
            }
        }
        // TODO: Support for Global Default configuration?
        return configs;
    }
}