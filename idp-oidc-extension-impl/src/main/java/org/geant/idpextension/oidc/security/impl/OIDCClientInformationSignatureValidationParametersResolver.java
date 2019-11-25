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

package org.geant.idpextension.oidc.security.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.spec.SecretKeySpec;

import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.impl.BasicSignatureSigningParametersResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Predicate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.jose.jwk.AsymmetricJWK;

/**
 * A specialization of {@link BasicSignatureSigningParametersResolver} which supports selecting signature validation
 * credentials based on client registration data. If the resolver fails to resolve credentials it leaves the job to the
 * hands of the super class method.
 * 
 * <p>
 * In addition to the {@link net.shibboleth.utilities.java.support.resolver.Criterion} inputs documented in
 * {@link BasicSignatureSigningParametersResolver}, the following inputs are also supported:
 * <ul>
 * <li>{@link ClientInformationCriterion} - optional</li>
 * </ul>
 * </p>
 */
public class OIDCClientInformationSignatureValidationParametersResolver
        extends BasicSignatureSigningParametersResolver {

    /** Logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(OIDCClientInformationSignatureValidationParametersResolver.class);

    /**
     * Whether to create parameters for request object signature validation or token endpoint jwt validation.
     */
    public enum ParameterType {
        REQUEST_OBJECT_VALIDATION, TOKEN_ENDPOINT_JWT_VALIDATION;
    }

    private ParameterType target = ParameterType.REQUEST_OBJECT_VALIDATION;

    /**
     * Whether to create parameters for request object signature validation or token endpoint jwt validation.
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
        final SignatureSigningParameters params = new OIDCSignatureValidationParameters();

        resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);

        if (validate(params)) {
            if (((OIDCSignatureValidationParameters) params).getValidationCredentials().size() == 0) {
                // Super class has resolved single credential, try resorting to that
                BasicJWKCredential jwkCredential = new BasicJWKCredential();
                jwkCredential.setAlgorithm(JWSAlgorithm.parse(params.getSignatureAlgorithm()));
                jwkCredential.setPublicKey(params.getSigningCredential().getPublicKey());
                ((OIDCSignatureValidationParameters) params).getValidationCredentials().add(jwkCredential);
            }
            logResult(params);
            return params;
        } else {
            return null;
        }
    }

    /**
     * Helper to match ECKey curve to JWS algorithm ES256, ES384 and ES512.
     * 
     * @param curve curve to match.
     * @param algorithm algorithm to match.
     * @return true if key curve matches algorithm, otherwise false.
     */

    // TODO: move to helper
    private boolean curveMatchesESAlgorithm(Curve curve, JWSAlgorithm algorithm) {
        if (algorithm.equals(JWSAlgorithm.ES256)) {
            return curve.equals(Curve.P_256);
        }
        if (algorithm.equals(JWSAlgorithm.ES384)) {
            return curve.equals(Curve.P_384);
        }
        if (algorithm.equals(JWSAlgorithm.ES512)) {
            return curve.equals(Curve.P_521);
        }
        return false;
    }

    // Checkstyle: CyclomaticComplexity|ReturnCount OFF
    /** {@inheritDoc} */
    @Override
    protected void resolveAndPopulateCredentialAndSignatureAlgorithm(@Nonnull final SignatureSigningParameters params,
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

        log.debug("Resolving SignatureSigningParameters, purpose {}",
                target.equals(ParameterType.REQUEST_OBJECT_VALIDATION) ? "request object signature validation"
                        : "token endpoint jwt signature validation");

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
        final List<String> algorithms = getEffectiveSignatureAlgorithms(criteria, whitelistBlacklistPredicate);
        log.trace("Resolved effective signature algorithms: {}", algorithms);
        JWSAlgorithm algorithm = (target == ParameterType.REQUEST_OBJECT_VALIDATION)
                ? clientInformation.getOIDCMetadata().getRequestObjectJWSAlg()
                : clientInformation.getOIDCMetadata().getTokenEndpointAuthJWSAlg();
        if (algorithm != null && !algorithms.contains(algorithm.getName())) {
            log.warn("Client requests algorithm {} that is not available", algorithm.getName());
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
            return;
        }

        List<JWSAlgorithm> supportedAlgos =
                algorithm == null ? convertToJWSAlgorithmList(algorithms) : Arrays.asList(algorithm);
        // Initialize HS family credentials
        for (JWSAlgorithm alg : supportedAlgos) {
            if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {
                if (clientInformation.getSecret() == null) {
                    log.debug("No client secret to use as a key");
                    break;
                }
                BasicJWKCredential jwkCredential = new BasicJWKCredential();
                jwkCredential.setSecretKey(new SecretKeySpec(clientInformation.getSecret().getValueBytes(), "NONE"));
                jwkCredential.setAlgorithm(alg);
                log.trace("HS Credential initialized from client secret for algorithm {}", alg.getName());
                params.setSigningCredential(jwkCredential);
                params.setSignatureAlgorithm(alg.getName());
                ((OIDCSignatureValidationParameters) params).getValidationCredentials().add(jwkCredential);
            }
        }
        // For EC&RSA family signature validation we pick all suitable keys from client's registration data
        JWKSet keySet = clientInformation.getOIDCMetadata().getJWKSet();
        if (keySet == null) {
            log.debug("No keyset available");
        } else {
            for (JWK key : keySet.getKeys()) {
                if (KeyUse.ENCRYPTION.equals(key.getKeyUse())) {
                    continue;
                }
                for (JWSAlgorithm alg : supportedAlgos) {
                    if ((JWSAlgorithm.Family.RSA.contains(alg) && key instanceof RSAKey)
                            || (JWSAlgorithm.Family.EC.contains(alg) && key instanceof ECKey
                                    && curveMatchesESAlgorithm(((ECKey) key).getCurve(), alg))) {
                        BasicJWKCredential jwkCredential = new BasicJWKCredential();
                        jwkCredential.setAlgorithm(alg);
                        jwkCredential.setKid(key.getKeyID());
                        try {
                            jwkCredential.setPublicKey(((AsymmetricJWK) key).toPublicKey());
                        } catch (JOSEException e) {
                            log.warn("Unable to parse key from keyset");
                            continue;
                        }
                        log.debug("Selected key {} for alg {}", key.getKeyID(), alg.getName());
                        params.setSigningCredential(jwkCredential);
                        params.setSignatureAlgorithm(alg.getName());
                        if (params instanceof OIDCSignatureValidationParameters) {
                            ((OIDCSignatureValidationParameters) params).getValidationCredentials().add(jwkCredential);
                            continue;
                        }
                    }
                }
            }
        }
        if (params.getSigningCredential() == null) {
            log.debug("Not able to resolve signature validation credential based on provided client information");
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
        }
    }

    /**
     * Convert algorithm string list to JWSAlgorithm list.
     * 
     * @param algorithms algorithm string list
     * @return JWSAlgorithm list
     */
    private List<JWSAlgorithm> convertToJWSAlgorithmList(List<String> algorithms) {
        List<JWSAlgorithm> jwsList = new ArrayList<JWSAlgorithm>();
        if (algorithms == null) {
            return jwsList;
        }
        for (String algorithm : algorithms) {
            jwsList.add(JWSAlgorithm.parse(algorithm));
        }
        return jwsList;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean validate(@Nonnull final SignatureSigningParameters params) {
        if (params.getSigningCredential() == null) {
            log.debug("Validation failure: Unable to resolve signature validation credential");
            return false;
        }
        if (params.getSignatureAlgorithm() == null) {
            log.debug("Validation failure: Unable to resolve signature validation algorithm URI");
            return false;
        }
        return true;
    }
}