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

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.security.impl.CredentialConversionUtil;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that serves both id token and user info response encryption. Existence of encryption parameters is taken as
 * indication whether the encryption should take place. Action assumes the content to be encrypted is located primarily
 * by {@link OidcResponseContext#getProcessedToken()} returning either signed id token or signed user info response. If
 * such information is not available action assumes the data to be encrypted is
 * {@link OidcResponseContext#.getUserInfo()} containing bare user info response. If neither of the sources for
 * encryption exists the actions fails.
 */
@SuppressWarnings("rawtypes")
public class EncryptProcessedToken extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(EncryptProcessedToken.class);

    /** Strategy used to look up the {@link EncryptionContext} to store parameters in. */
    @Nonnull
    private Function<ProfileRequestContext, EncryptionContext> encryptionContextLookupStrategy;

    /** Encryption parameters for encrypting payload. */
    private EncryptionParameters params;

    /** Payload to encrypt. */
    private Payload payload;

    /**
     * Constructor.
     */
    public EncryptProcessedToken() {
        encryptionContextLookupStrategy = Functions.compose(new ChildContextLookup<>(EncryptionContext.class, false),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
    }

    /**
     * Set the strategy used to look up the {@link EncryptionContext} to set the flags for.
     * 
     * @param strategy lookup strategy
     */
    public void setEncryptionContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, EncryptionContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        encryptionContextLookupStrategy =
                Constraint.isNotNull(strategy, "EncryptionContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        final EncryptionContext encryptCtx = encryptionContextLookupStrategy.apply(profileRequestContext);
        if (encryptCtx == null) {
            log.error("{} No EncryptionContext returned by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        params = encryptCtx.getAssertionEncryptionParameters();
        if (params == null) {
            log.debug("{} No Encryption parameters, nothing to do", getLogPrefix());
            return false;
        }
        if (getOidcResponseContext().getProcessedToken() != null) {
            payload = new Payload((SignedJWT) getOidcResponseContext().getProcessedToken());
        } else if (getOidcResponseContext().getUserInfo() != null) {
            payload = new Payload(getOidcResponseContext().getUserInfo().toJSONObject());
        }
        if (payload == null) {
            log.error("{} Instructed to encrypt but no plain text source available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        JWEAlgorithm encAlg = JWEAlgorithm.parse(params.getKeyTransportEncryptionAlgorithm());
        Credential credential = params.getKeyTransportEncryptionCredential();
        EncryptionMethod encEnc = EncryptionMethod.parse(params.getDataEncryptionAlgorithm());
        String kid = CredentialConversionUtil.resolveKid(credential);

        log.debug("{} encrypting with key {} and params alg: {} enc: {}", getLogPrefix(), kid, encAlg.getName(),
                encEnc.getName());

        JWEObject jweObject =
                new JWEObject(new JWEHeader.Builder(encAlg, encEnc).contentType("JWT").keyID(kid).build(), payload);
        try {
            if (JWEAlgorithm.Family.RSA.contains(encAlg)) {
                jweObject.encrypt(new RSAEncrypter((RSAPublicKey) credential.getPublicKey()));
            } else if (JWEAlgorithm.Family.ECDH_ES.contains(encAlg)) {
                jweObject.encrypt(new ECDHEncrypter((ECPublicKey) credential.getPublicKey()));
            } else if (JWEAlgorithm.Family.SYMMETRIC.contains(encAlg)) {
                jweObject.encrypt(new AESEncrypter(credential.getSecretKey()));
            } else {
                log.error("{} Unsupported algorithm {}", getLogPrefix(), encAlg.getName());
                ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
            }
            getOidcResponseContext().setProcessedToken(EncryptedJWT.parse(jweObject.serialize()));
        } catch (JOSEException | ParseException e) {
            log.error("{} Encryption failed {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
        }
    }

}