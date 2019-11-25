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

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.navigate.DataEncryptionAlgorithmsLookupFunction;
import org.geant.idpextension.oidc.config.navigate.KeyTransportEncryptionAlgorithmsLookupFunction;
import org.geant.idpextension.oidc.config.navigate.SignatureAlgorithmsLookupFunction;
import org.geant.idpextension.oidc.crypto.support.SignatureConstants;
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
    
    /** Whether signature algorithm none is allowed regardless of what list of Signature Validation Algs has. */
    @Nonnull
    private boolean allowSignatureNone;

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
     * Set whether signature algorithm none is allowed regardless of what list of Signature Validation Algs has.
     * 
     * @param allow Whether signature algorithm none is allowed regardless of what list of Signature
     *            Validation Algs has
     */
    public void setAllowSignatureNone(boolean allow) {
        allowSignatureNone = allow;
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
        //"none" should be supported by every op. "none" cannot be found from the supported algs list.
        if (reqRequestObjectSigAlg != null) {
            if ((SignatureConstants.ALGO_ID_SIGNATURE_NONE.equals(reqRequestObjectSigAlg.getName())
                    && allowSignatureNone)
                    || supportedSignatureValidationAlgs.contains(reqRequestObjectSigAlg.getName())) {
                getOutputMetadata().setRequestObjectJWSAlg(reqRequestObjectSigAlg);
            } else {
                log.warn("{} The requested request_object_signing_alg {} is not supported", getLogPrefix(),
                        reqRequestObjectSigAlg.getName());
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
