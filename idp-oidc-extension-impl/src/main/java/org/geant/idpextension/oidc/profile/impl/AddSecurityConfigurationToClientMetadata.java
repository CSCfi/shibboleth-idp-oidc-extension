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
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ResponseType;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Verifies and adds the security configuration details (*_response_alg and *_response_enc) to the client metadata.
 */
public class AddSecurityConfigurationToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddSecurityConfigurationToClientMetadata.class);

    /** Strategy to obtain list of supported signature algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> signatureAlgorithmsLookupStrategy;

    /** Strategy to obtain list of supported data encryption algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> dataEncryptionAlgorithmsLookupStrategy;

    /** Strategy to obtain list of supported key transport encryption algorithms. */
    @Nullable private Function<ProfileRequestContext,List<String>> keyTransportEncryptionAlgorithmsLookupStrategy;

    /**
     * List of supported signing algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedSigningAlgs;

    /**
     * List of supported data encryption algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedEncryptionEncs;

    /**
     * List of supported key transport algorithms obtained from the security configuration.
     */
    @Nullable
    List<String> supportedEncryptionAlgs;

    public AddSecurityConfigurationToClientMetadata() {
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
        
        supportedSigningAlgs = signatureAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedSigningAlgs.isEmpty()) {
            log.warn("{} No supported signature signing algorithms resolved", getLogPrefix());
        }

        supportedEncryptionAlgs = keyTransportEncryptionAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedEncryptionAlgs.isEmpty()) {
            log.warn("{} No supported key transport encryption algorithms resolved", getLogPrefix());
        }
        
        supportedEncryptionEncs = dataEncryptionAlgorithmsLookupStrategy.apply(profileRequestContext);
        if (supportedEncryptionEncs.isEmpty()) {
            log.warn("{} No supported data encryption algorithms resolved", getLogPrefix());
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final JWSAlgorithm reqIdTokenSigAlg = getInputMetadata().getIDTokenJWSAlg();
        if (reqIdTokenSigAlg == null) {
            getOutputMetadata().setIDTokenJWSAlg(new JWSAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RS_256));
        } else {
            getOutputMetadata().setIDTokenJWSAlg(reqIdTokenSigAlg);
        }
        if (supportedSigningAlgs.contains(getOutputMetadata().getIDTokenJWSAlg().getName())) {
            boolean implicitOrHybrid = false;
            if (getOutputMetadata().getResponseTypes() != null) {
                for (final ResponseType responseType : getOutputMetadata().getResponseTypes()) {
                    if (responseType.impliesHybridFlow() || responseType.impliesImplicitFlow()) {
                        implicitOrHybrid = true;
                        break;
                    }
                }
            }
            if (getOutputMetadata().getIDTokenJWSAlg().equals(Algorithm.NONE) && implicitOrHybrid) {
                log.warn(
                        "{} The requested id_token_signed_response_alg 'none' is not supported when implicit or hybrid flow in response type",
                        getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
        } else {
            log.warn("{} The requested id_token_signed_response_alg {} is not supported", getLogPrefix(),
                    getOutputMetadata().getIDTokenJWSAlg().getName());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }

        final JWSAlgorithm reqUserInfoSigAlg = getInputMetadata().getUserInfoJWSAlg();
        if (reqUserInfoSigAlg != null) {
            if (supportedSigningAlgs.contains(reqUserInfoSigAlg.getName())) {
                getOutputMetadata().setUserInfoJWSAlg(reqUserInfoSigAlg);
            } else {
                log.warn("{} The requested userinfo_signed_response_alg {} is not supported", getLogPrefix(),
                        reqUserInfoSigAlg.getName());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
        }

        final JWEAlgorithm reqIdTokenEncAlg = getInputMetadata().getIDTokenJWEAlg();
        final EncryptionMethod reqIdTokenEncEnc = getInputMetadata().getIDTokenJWEEnc();
        if ((reqIdTokenEncAlg == null) != (reqIdTokenEncEnc == null)) {
            if (reqIdTokenEncAlg == null) {
                log.warn("{} The requested id_token_encrypted_response_alg was not defined even though _enc was",
                        getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            } else {
                log.debug("{} Using default algorithm for id_token_encrypted_response_alg", getLogPrefix());
                getOutputMetadata().setIDTokenJWEEnc(EncryptionMethod.A128CBC_HS256);
                getOutputMetadata().setIDTokenJWEAlg(reqIdTokenEncAlg);
            }
        } else {
            getOutputMetadata().setIDTokenJWEAlg(getInputMetadata().getIDTokenJWEAlg());
            getOutputMetadata().setIDTokenJWEEnc(getInputMetadata().getIDTokenJWEEnc());
        }

        if (getOutputMetadata().getIDTokenJWEAlg() != null
                && !supportedEncryptionAlgs.contains(getOutputMetadata().getIDTokenJWEAlg().getName())) {
            log.warn("{} The requested id_token_encrypted_response_alg {} is not supported", getLogPrefix(),
                    getOutputMetadata().getIDTokenJWEAlg());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        if (getOutputMetadata().getIDTokenJWEEnc() != null
                && !supportedEncryptionEncs.contains(getOutputMetadata().getIDTokenJWEEnc().getName())) {
            log.warn("{} The requested id_token_encrypted_response_enc {} is not supported", getLogPrefix(),
                    getOutputMetadata().getIDTokenJWEEnc());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }

        final JWEAlgorithm reqUserInfoEncAlg = getInputMetadata().getUserInfoJWEAlg();
        final EncryptionMethod reqUserInfoEncEnc = getInputMetadata().getUserInfoJWEEnc();
        if ((reqUserInfoEncAlg == null) != (reqUserInfoEncEnc == null)) {
            if (reqUserInfoEncAlg == null) {
                log.warn("{} The requested userinfo_encrypted_response_alg was not defined even though _enc was",
                        getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            } else {
                log.debug("{} Using default algorithm for userinfo_encrypted_response_alg", getLogPrefix());
                getOutputMetadata().setUserInfoJWEEnc(EncryptionMethod.A128CBC_HS256);
                getOutputMetadata().setUserInfoJWEAlg(reqUserInfoEncAlg);
            }
        } else {
            getOutputMetadata().setUserInfoJWEAlg(getInputMetadata().getUserInfoJWEAlg());
            getOutputMetadata().setUserInfoJWEEnc(getInputMetadata().getUserInfoJWEEnc());
        }

        if (getOutputMetadata().getUserInfoJWEAlg() != null
                && !supportedEncryptionAlgs.contains(getOutputMetadata().getUserInfoJWEAlg().getName())) {
            log.warn("{} The requested userinfo_encrypted_response_alg {} is not supported", getLogPrefix(),
                    getOutputMetadata().getUserInfoJWEAlg());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        if (getOutputMetadata().getUserInfoJWEEnc() != null
                && !supportedEncryptionEncs.contains(getOutputMetadata().getUserInfoJWEEnc().getName())) {
            log.warn("{} The requested userinfo_encrypted_response_enc {} is not supported", getLogPrefix(),
                    getOutputMetadata().getUserInfoJWEEnc());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }

        // org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_MAC_HMAC_SHA512;
    }

}
