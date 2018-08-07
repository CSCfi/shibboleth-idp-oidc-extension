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

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.signature.support.SignatureConstants;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ResponseType;

import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Verifies and adds the security configuration details (*_response_alg and *_response_enc) to the client metadata.
 */
public class AddSecurityConfigurationToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddSecurityConfigurationToClientMetadata.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** The RelyingPartyContext to operate on. */
    @Nullable
    private RelyingPartyContext rpCtx;

    public AddSecurityConfigurationToClientMetadata() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }

        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.debug("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }

        if (rpCtx.getProfileConfig() == null) {
            log.debug("{} No profile configuration associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final ProfileConfiguration profileConfig = rpCtx.getProfileConfig();

        final SignatureSigningConfiguration sigConfig =
                profileConfig.getSecurityConfiguration().getSignatureSigningConfiguration();
        final List<String> supportedSigningAlgs = sigConfig.getSignatureAlgorithms();

        final JWSAlgorithm reqIdTokenSigAlg = getInputMetadata().getIDTokenJWSAlg();
        if (reqIdTokenSigAlg == null) {
            // TODO: should we double-check that RS256 is supported by the profile configuration?
            getOutputMetadata().setIDTokenJWSAlg(new JWSAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RS_256));
        } else {
            final String algName = reqIdTokenSigAlg.getName();
            if (supportedSigningAlgs.contains(algName)) {
                boolean implicitOrHybrid = false;
                for (final ResponseType responseType : getOutputMetadata().getResponseTypes()) {
                    if (responseType.impliesHybridFlow() || responseType.impliesImplicitFlow()) {
                        implicitOrHybrid = true;
                        break;
                    }
                }
                if (reqIdTokenSigAlg.equals(Algorithm.NONE) && implicitOrHybrid) {
                    log.warn(
                            "{} The requested id_token_signed_response_alg 'none' is not supported when implicit or hybrid flow in response type",
                            getLogPrefix());
                    ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                    return;
                }
                getOutputMetadata().setIDTokenJWSAlg(reqIdTokenSigAlg);
            } else {
                log.warn("{} The requested id_token_signed_response_alg {} is not supported", getLogPrefix(), algName);
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
        }

        final JWSAlgorithm reqUserInfoSigAlg = getInputMetadata().getUserInfoJWSAlg();
        if (reqUserInfoSigAlg != null) {
            final String algName = reqUserInfoSigAlg.getName();
            if (supportedSigningAlgs.contains(algName)) {
                getOutputMetadata().setUserInfoJWSAlg(reqUserInfoSigAlg);
            } else {
                log.warn("{} The requested userinfo_signed_response_alg {} is not supported", getLogPrefix(), algName);
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
        }

        // TODO: finish this
        final EncryptionConfiguration encConfig = profileConfig.getSecurityConfiguration().getEncryptionConfiguration();

        // org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_MAC_HMAC_SHA512;
    }

}
