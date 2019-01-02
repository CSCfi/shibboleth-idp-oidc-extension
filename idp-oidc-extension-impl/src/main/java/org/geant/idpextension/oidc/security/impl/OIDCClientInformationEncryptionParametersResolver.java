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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.annotation.Nonnull;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.geant.idpextension.oidc.criterion.ClientInformationCriterion;
import org.geant.security.jwk.BasicJWKCredential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.criterion.EncryptionOptionalCriterion;
import org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * A specialization of {@link BasicEncryptionParametersResolver} which resolves credentials and algorithm preferences
 * against client registration data.
 * 
 * <p>
 * In addition to the {@link net.shibboleth.utilities.java.support.resolver.Criterion} inputs documented in
 * {@link BasicEncryptionParametersResolver}, the inputs and associated modes of operation documented for
 * {@link ClientInformationCriterion} are also supported.
 * </p>
 * 
 */
public class OIDCClientInformationEncryptionParametersResolver extends BasicEncryptionParametersResolver {

    /** Logger. */
    private Logger log = LoggerFactory.getLogger(OIDCClientInformationEncryptionParametersResolver.class);

    /** Whether we resolve parameters for id token or user info response encryption. */
    private boolean userInfoSigningResolver;

    /**
     * Whether we resolve parameters for id token or user info response encryption.
     * 
     * @param userInfoSigningResolver true if resolving done for user info response and not for id token encryption.
     */
    public void setUserInfoSigningResolver(boolean value) {
        userInfoSigningResolver = value;
    }

    /** {@inheritDoc} */
    @Override
    protected void resolveAndPopulateCredentialsAndAlgorithms(@Nonnull final EncryptionParameters params,
            @Nonnull final CriteriaSet criteria, @Nonnull final Predicate<String> whitelistBlacklistPredicate) {

        if (!criteria.contains(ClientInformationCriterion.class)) {
            log.debug("No client criterion, nothing to do");
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        OIDCClientInformation clientInformation =
                criteria.get(ClientInformationCriterion.class).getOidcClientInformation();
        if (clientInformation == null) {
            log.debug("No client information, nothing to do");
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        // Check the requirements from metadatata, algorithm, need for algorithm
        JWEAlgorithm keyTransportAlgorithm =
                userInfoSigningResolver == true ? clientInformation.getOIDCMetadata().getUserInfoJWEAlg()
                        : clientInformation.getOIDCMetadata().getIDTokenJWEAlg();
        EncryptionMethod encryptionMethod =
                userInfoSigningResolver == true ? clientInformation.getOIDCMetadata().getUserInfoJWEEnc()
                        : clientInformation.getOIDCMetadata().getIDTokenJWEEnc();
        if (keyTransportAlgorithm == null) {
            log.debug("No {} in client information, nothing to do", userInfoSigningResolver == true
                    ? "userinfo_encrypted_response_alg" : "id_token_encrypted_response_alg");
            criteria.add(new EncryptionOptionalCriterion(true));
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        if (encryptionMethod == null) {
            encryptionMethod = EncryptionMethod.A128CBC_HS256;
        }
        final List<String> keyTransportAlgorithms =
                getEffectiveKeyTransportAlgorithms(criteria, whitelistBlacklistPredicate);
        log.trace("Resolved effective key transport algorithms: {}", keyTransportAlgorithms);
        if (!keyTransportAlgorithms.contains(keyTransportAlgorithm.getName())) {
            log.warn("Client requests key transport algorithm {} that is not available",
                    keyTransportAlgorithm.getName());
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        final List<String> dataEncryptionAlgorithms =
                getEffectiveDataEncryptionAlgorithms(criteria, whitelistBlacklistPredicate);
        log.trace("Resolved effective data encryption algorithms: {}", dataEncryptionAlgorithms);
        if (!dataEncryptionAlgorithms.contains(encryptionMethod.getName())) {
            log.warn("Client requests encryption algorithm {} that is not available", encryptionMethod.getName());
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        // AES + client secret based key transports:
        if (JWEAlgorithm.Family.SYMMETRIC.contains(keyTransportAlgorithm)) {
            Secret secret = clientInformation.getSecret();
            if (secret == null) {
                log.warn("No client secret available");
                super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            BasicJWKCredential jwkCredential = new BasicJWKCredential();
            jwkCredential.setAlgorithm(keyTransportAlgorithm);
            try {
                jwkCredential.setSecretKey(generateSymmetricKey(secret.getValueBytes(), keyTransportAlgorithm));
            } catch (NoSuchAlgorithmException e) {
                log.warn("Unable to generate secret key: " + e.getMessage());
                super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
                return;
            }
            params.setKeyTransportEncryptionCredential(jwkCredential);
            params.setKeyTransportEncryptionAlgorithm(keyTransportAlgorithm.getName());
            params.setDataEncryptionAlgorithm(encryptionMethod.getName());
            return;
        }
        // RSA & EC based key transports
        JWKSet keySet = clientInformation.getOIDCMetadata().getJWKSet();
        if (keySet == null) {
            log.warn("No keyset available");
            super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
            return;
        }
        for (JWK key : keySet.getKeys()) {
            if (KeyUse.SIGNATURE.equals(key.getKeyUse())) {
                continue;
            }
            if ((JWEAlgorithm.Family.RSA.contains(keyTransportAlgorithm) && key.getKeyType().equals(KeyType.RSA))
                    || (JWEAlgorithm.Family.ECDH_ES.contains(keyTransportAlgorithm)
                            && key.getKeyType().equals(KeyType.EC))) {
                BasicJWKCredential jwkCredential = new BasicJWKCredential();
                jwkCredential.setAlgorithm(keyTransportAlgorithm);
                jwkCredential.setKid(key.getKeyID());
                try {
                    if (key.getKeyType().equals(KeyType.RSA)) {
                        jwkCredential.setPublicKey(((RSAKey) key).toPublicKey());
                    } else {
                        jwkCredential.setPublicKey(((ECKey) key).toPublicKey());
                    }
                } catch (JOSEException e) {
                    log.warn("Unable to parse keyset");
                    super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
                    return;
                }
                log.debug("Selected key {} for alg {} and enc {}", key.getKeyID(), keyTransportAlgorithm.getName(),
                        encryptionMethod.getName());
                params.setKeyTransportEncryptionCredential(jwkCredential);
                params.setKeyTransportEncryptionAlgorithm(keyTransportAlgorithm.getName());
                params.setDataEncryptionAlgorithm(encryptionMethod.getName());
                return;
            }

        }
        super.resolveAndPopulateCredentialsAndAlgorithms(params, criteria, whitelistBlacklistPredicate);
    }

    /**
     * Generate symmetric key from client secret.
     * 
     * @param clientSecret client secret that is the basis of key
     * @param keyTransportAlgorithm algorithm the key is generated for
     * @return key derived from client secret.
     * @throws NoSuchAlgorithmException if algorithm or digest method is unsupported
     */
    private SecretKey generateSymmetricKey(byte[] clientSecret, JWEAlgorithm keyTransportAlgorithm)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        switch (keyTransportAlgorithm.getName()) {
            case "A128KW":
            case "A128GCMKW":
                return new SecretKeySpec(md.digest(clientSecret), 0, 16, "AES");
            case "A192KW":
            case "A192GCMKW":
                return new SecretKeySpec(md.digest(clientSecret), 0, 24, "AES");
            case "A256KW":
            case "A256GCMKW":
                return new SecretKeySpec(md.digest(clientSecret), 0, 32, "AES");
        }
        throw new NoSuchAlgorithmException(
                "Implementation does not support generating key for " + keyTransportAlgorithm.getName());
    }

}
