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

import org.geant.idpextension.oidc.config.navigate.DataEncryptionAlgorithmsLookupFunction;
import org.geant.idpextension.oidc.config.navigate.KeyTransportEncryptionAlgorithmsLookupFunction;
import org.geant.idpextension.oidc.config.navigate.SignatureAlgorithmsLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Verifies and adds the request object configuration details (request_object_signing_alg, request_object_encryption_alg and request_object_encryption_enc) to the client metadata.
 */
public class AddRequestObjectSecurityConfigurationToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddRequestObjectSecurityConfigurationToClientMetadata.class);

    /** Strategy to obtain list of supported signature algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> signatureAlgorithmsLookupStrategy;

    /** Strategy to obtain list of supported data encryption algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> dataEncryptionAlgorithmsLookupStrategy;

    /** Strategy to obtain list of supported key transport encryption algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> keyTransportEncryptionAlgorithmsLookupStrategy;
    
    /**
     * List of supported signature validation algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedSignatureValidationAlgs;

    /**
     * List of supported data decryption algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedDecryptionEncs;

    /**
     * List of supported key transport algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedDecryptionAlgs;

    public AddRequestObjectSecurityConfigurationToClientMetadata() {
        signatureAlgorithmsLookupStrategy = new SignatureAlgorithmsLookupFunction();
        dataEncryptionAlgorithmsLookupStrategy = new DataEncryptionAlgorithmsLookupFunction();
        keyTransportEncryptionAlgorithmsLookupStrategy = new KeyTransportEncryptionAlgorithmsLookupFunction();
    }

    /**
     * Set the strategy used to obtain list of supported signature algorithms.
     * 
     * @param strategy What to set.
     */
    public void setSignatureAlgorithmsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,List<String>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        signatureAlgorithmsLookupStrategy =
                Constraint.isNotNull(strategy, "Signature algorithms lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to obtain list of supported signature algorithms.
     * 
     * @param strategy What to set.
     */
    public void setDataEncryptionAlgorithmsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,List<String>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        dataEncryptionAlgorithmsLookupStrategy =
                Constraint.isNotNull(strategy, "Data encryption algorithms lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to obtain list of supported signature algorithms.
     * 
     * @param strategy What to set.
     */
    public void setKeyTransportAlgorithmsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,List<String>> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        keyTransportEncryptionAlgorithmsLookupStrategy =
                Constraint.isNotNull(strategy, "Key transport encryption algorithms lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        
        supportedSignatureValidationAlgs = signatureAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedSignatureValidationAlgs.isEmpty()) {
            log.warn("{} No supported signature validation algorithms resolved", getLogPrefix());
        }

        supportedDecryptionAlgs = keyTransportEncryptionAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedDecryptionAlgs.isEmpty()) {
            log.warn("{} No supported key transport decryption algorithms resolved", getLogPrefix());
        }
        
        supportedDecryptionEncs = dataEncryptionAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedDecryptionEncs.isEmpty()) {
            log.warn("{} No supported data decryption algorithms resolved", getLogPrefix());
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final JWSAlgorithm reqRequestObjectSigAlg = getInputMetadata().getRequestObjectJWSAlg();
        if (reqRequestObjectSigAlg != null) {
            if (supportedSignatureValidationAlgs.contains(reqRequestObjectSigAlg.getName())) {
                getOutputMetadata().setRequestObjectJWSAlg(reqRequestObjectSigAlg);
            } else {
                log.warn(
                        "{} The requested request_object_signing_alg {} is not supported",
                        getLogPrefix(), reqRequestObjectSigAlg.getName());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;                
            }
        }
        

        final JWEAlgorithm reqRequestObjectEncAlg = getInputMetadata().getRequestObjectJWEAlg();
        final EncryptionMethod reqRequestObjectEncEnc = getInputMetadata().getRequestObjectJWEEnc();
        if ((reqRequestObjectEncAlg == null) != (reqRequestObjectEncEnc == null)) {
            if (reqRequestObjectEncAlg == null) {
                log.warn("{} The requested request_object_encryption_alg was not defined even though _enc was",
                        getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            } else {
                log.debug("{} Using default algorithm for request_object_encryption_enc", getLogPrefix());
                getOutputMetadata().setRequestObjectJWEEnc(EncryptionMethod.A128CBC_HS256);
                getOutputMetadata().setRequestObjectJWEAlg(reqRequestObjectEncAlg);
            }
        } else {
            getOutputMetadata().setRequestObjectJWEAlg(getInputMetadata().getRequestObjectJWEAlg());
            getOutputMetadata().setRequestObjectJWEEnc(getInputMetadata().getRequestObjectJWEEnc());
        }

        if (getOutputMetadata().getRequestObjectJWEAlg() != null
                && !supportedDecryptionAlgs.contains(getOutputMetadata().getRequestObjectJWEAlg().getName())) {
            log.warn("{} The requested response_object_encryption_alg {} is not supported", getLogPrefix(),
                    getOutputMetadata().getRequestObjectJWEAlg());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        if (getOutputMetadata().getRequestObjectJWEEnc() != null
                && !supportedDecryptionEncs.contains(getOutputMetadata().getRequestObjectJWEEnc().getName())) {
            log.warn("{} The requested response_object_encryption_enc {} is not supported", getLogPrefix(),
                    getOutputMetadata().getRequestObjectJWEEnc());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
    }

}
