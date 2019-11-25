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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * A specialization of {@link BasicSignatureSigningParametersResolver} which supports selecting signing credentials
 * based on client registration data and instantiating HS credentials when needed. If the resolver fails to resolve
 * credentials it leaves the job to the hands of the super class method.
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
     * Whether to create parameters for id token signing or userinfo response signing.
     */
    public enum ParameterType {
        IDTOKEN_SIGNING, USERINFO_SIGNING
    }

    private ParameterType target = ParameterType.IDTOKEN_SIGNING;

    /**
     * Whether to create parameters for id token signing or userinfo response signing.
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
        final SignatureSigningParameters params = new SignatureSigningParameters();

        resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);

        if (validate(params)) {
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
    // TODO: Move to helper
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
                target.equals(ParameterType.IDTOKEN_SIGNING) ? "id token signing" : "userinfo response signing");

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
        JWSAlgorithm algorithm =
                target == ParameterType.IDTOKEN_SIGNING ? clientInformation.getOIDCMetadata().getIDTokenJWSAlg()
                        : clientInformation.getOIDCMetadata().getUserInfoJWSAlg();
        if (algorithm == null) {
            if (target == ParameterType.USERINFO_SIGNING) {
                log.debug("No alg defined in client information, nothing to do");
                super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            if (target == ParameterType.IDTOKEN_SIGNING) {
                algorithm = JWSAlgorithm.RS256;
            }
        }
        if (algorithm != null && !algorithms.contains(algorithm.getName())) {
            log.warn("Client requests algorithm {} that is not available", algorithm.getName());
            super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        // If HS family is requested we create the credential from client secret
        if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
            if (clientInformation.getSecret() == null) {
                log.warn("No client secret to use as a key");
                super.resolveAndPopulateCredentialAndSignatureAlgorithm(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            BasicJWKCredential jwkCredential = new BasicJWKCredential();
            jwkCredential.setSecretKey(new SecretKeySpec(clientInformation.getSecret().getValueBytes(), "NONE"));
            jwkCredential.setAlgorithm(algorithm);
            log.trace("HS Credential initialized from client secret for algorithm {}", algorithm.getName());
            params.setSigningCredential(jwkCredential);
            params.setSignatureAlgorithm(algorithm.getName());
            return;
        }
        // Lets pick first matching credential for the algorithm
        for (Credential credential : credentials) {
            if ((JWSAlgorithm.Family.RSA.contains(algorithm) && (credential.getPrivateKey() instanceof RSAPrivateKey))
                    || (JWSAlgorithm.Family.EC.contains(algorithm)
                            && (credential.getPrivateKey() instanceof ECPrivateKey)
                            && curveMatchesESAlgorithm(
                                    Curve.forECParameterSpec(
                                            ((java.security.interfaces.ECKey) credential.getPrivateKey()).getParams()),
                                    algorithm))) {
                log.trace("Credential picked for algorithm {}", algorithm.getName());
                params.setSigningCredential(credential);
                params.setSignatureAlgorithm(algorithm.getName());
                return;
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
            log.debug("Validation failure: Unable to resolve signing credential");
            return false;
        }
        if (params.getSignatureAlgorithm() == null) {
            log.debug("Validation failure: Unable to resolve signing algorithm URI");
            return false;
        }
        return true;
    }
}