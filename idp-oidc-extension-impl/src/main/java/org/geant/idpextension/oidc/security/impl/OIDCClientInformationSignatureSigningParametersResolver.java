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

package org.geant.idpextension.oidc.security.impl;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.spec.SecretKeySpec;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicSignatureSigningParametersResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Predicate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * A specialization of {@link BasicSignatureSigningParametersResolver} which supports selecting signing and signature
 * validation credentials based on client registration data and instantiating HS credentials when needed. If the
 * resolver fails to resolve credentials it leaves the job to the hands of the super class method.
 * 
 * <p>
 * In addition to the {@link net.shibboleth.utilities.java.support.resolver.Criterion} inputs documented in
 * {@link BasicSignatureSigningParametersResolver}, the following inputs are also supported:
 * <ul>
 * <li>{@link ClientInformationCriterion} - optional</li>
 * </ul>
 * </p>
 */
public class OIDCClientInformationSignatureSigningParametersResolver extends BasicSignatureSigningParametersResolver {

    /** Logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(OIDCClientInformationSignatureSigningParametersResolver.class);

    /**
     * Whether to create parameters for request object signature validation, id token signing or userinfo response
     * signing.
     */
    public enum ParameterType {
        REQUEST_OBJECT_VALIDATION, IDTOKEN_SIGNING, USERINFO_SIGNING
    }

    private ParameterType target = ParameterType.IDTOKEN_SIGNING;

    /**
     * Whether to create parameters for request object signature validation, id token signing or userinfo response
     * signing.
     * 
     * @param target Whether to create parameters for request object signature validation, id token signing or userinfo
     *            response signing.
     * 
     */
    public void setParameterType(ParameterType value) {
        target = value;
    }

    /** {@inheritDoc} */
    @Nullable
    public SignatureSigningParameters resolveSingle(@Nonnull final CriteriaSet criteria) throws ResolverException {
        Constraint.isNotNull(criteria, "CriteriaSet was null");
        Constraint.isNotNull(criteria.get(SignatureSigningConfigurationCriterion.class),
                "Resolver requires an instance of SignatureSigningConfigurationCriterion");

        final Predicate<String> whitelistBlacklistPredicate = getWhitelistBlacklistPredicate(criteria);

        // For signature validation we need to list all the located keys and need the extended
        // SignatureSigningParameters
        final SignatureSigningParameters params = (target == ParameterType.REQUEST_OBJECT_VALIDATION)
                ? new OIDCSignatureValidationParameters() : new SignatureSigningParameters();

        resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);

        if (validate(params)) {
            logResult(params);
            return params;
        } else {
            return null;
        }
    }

    // Checkstyle: CyclomaticComplexity|ReturnCount OFF
    /** {@inheritDoc} */
    @Override
    protected void resolveAndPopulateCredentialAndSignatureAlgorithm(@Nonnull final SignatureSigningParameters params,
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

        if (!criteria.contains(ClientInformationCriterion.class)) {
            log.debug("No client criterion, nothing to do");
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        OIDCClientInformation clientInformation =
                criteria.get(ClientInformationCriterion.class).getOidcClientInformation();
        if (clientInformation == null) {
            log.debug("No client information, nothing to do");
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        final List<Credential> credentials = getEffectiveSigningCredentials(criteria);
        final List<String> algorithms = getEffectiveSignatureAlgorithms(criteria, whitelistBlacklistPredicate);
        log.trace("Resolved effective signature algorithms: {}", algorithms);
        JWSAlgorithm algorithm = null;
        switch (target) {
            case REQUEST_OBJECT_VALIDATION:
                algorithm = clientInformation.getOIDCMetadata().getRequestObjectJWSAlg();
                break;

            case USERINFO_SIGNING:
                algorithm = clientInformation.getOIDCMetadata().getUserInfoJWSAlg();
                break;

            default:
                algorithm = clientInformation.getOIDCMetadata().getIDTokenJWSAlg();
        }
        if (algorithm == null) {
            if (target != ParameterType.IDTOKEN_SIGNING) {
                log.debug("No alg defined in client information, nothing to do");
                super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            algorithm = JWSAlgorithm.RS256;
        }
        if (!algorithms.contains(algorithm.getName())) {
            log.warn("Client requests algorithm {} that is not available", algorithm.getName());
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        // For HS family we need to create the credential now
        if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
            if (clientInformation.getSecret() == null) {
                log.warn("No client secret to use as a key");
                super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            BasicJWKCredential jwkCredential = new BasicJWKCredential();
            jwkCredential.setSecretKey(new SecretKeySpec(clientInformation.getSecret().getValueBytes(), "NONE"));
            jwkCredential.setAlgorithm(algorithm);
            log.trace("HS Credential initialized from client secret");
            params.setSigningCredential(jwkCredential);
            params.setSignatureAlgorithm(algorithm.getName());
            return;
        }
        if (target != ParameterType.REQUEST_OBJECT_VALIDATION) {
            // For EC&RSA family signing we locate the first credential of correct type
            for (Credential credential : credentials) {
                if ((JWSAlgorithm.Family.RSA.contains(algorithm)
                        && (credential.getPrivateKey() instanceof RSAPrivateKey))
                        || (JWSAlgorithm.Family.EC.contains(algorithm)
                                && (credential.getPrivateKey() instanceof ECPrivateKey))) {
                    log.trace("Credential picked for algorithm {}", algorithm.getName());
                    params.setSigningCredential(credential);
                    params.setSignatureAlgorithm(algorithm.getName());
                    return;
                }
            }
        } else {// For EC&RSA family signature validation we pick all suitable keys from client's registration data
            JWKSet keySet = clientInformation.getOIDCMetadata().getJWKSet();
            if (keySet == null) {
                log.warn("No keyset available");
                super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            for (JWK key : keySet.getKeys()) {
                if (KeyUse.ENCRYPTION.equals(key.getKeyUse())) {
                    continue;
                }
                if ((JWSAlgorithm.Family.RSA.contains(algorithm) && key.getKeyType().equals(KeyType.RSA))
                        || (JWSAlgorithm.Family.EC.contains(algorithm) && key.getKeyType().equals(KeyType.EC))) {
                    BasicJWKCredential jwkCredential = new BasicJWKCredential();
                    jwkCredential.setAlgorithm(algorithm);
                    jwkCredential.setKid(key.getKeyID());
                    try {
                        if (key.getKeyType().equals(KeyType.RSA)) {
                            jwkCredential.setPublicKey(((RSAKey) key).toPublicKey());
                        } else {
                            jwkCredential.setPublicKey(((ECKey) key).toPublicKey());
                        }
                    } catch (JOSEException e) {
                        log.warn("Unable to parse keyset");
                        super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria,
                                whitelistBlacklistPredicate);
                        return;
                    }
                    log.debug("Selected key {} for alg {}", key.getKeyID(), algorithm.getName());
                    params.setSigningCredential(jwkCredential);
                    params.setSignatureAlgorithm(algorithm.getName());
                    if (params instanceof OIDCSignatureValidationParameters) {
                        ((OIDCSignatureValidationParameters) params).getValidationCredentials().add(jwkCredential);
                        continue;
                    }
                    return;
                }
            }
        }
        if (params.getSigningCredential() == null) {
            log.debug("Not able to resolve signing credential based on provided client information");
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean validate(@Nonnull final SignatureSigningParameters params) {
        if (params.getSigningCredential() == null) {
            log.warn("Validation failure: Unable to resolve signing credential");
            return false;
        }
        if (params.getSignatureAlgorithm() == null) {
            log.warn("Validation failure: Unable to resolve signing algorithm URI");
            return false;
        }
        return true;
    }
}