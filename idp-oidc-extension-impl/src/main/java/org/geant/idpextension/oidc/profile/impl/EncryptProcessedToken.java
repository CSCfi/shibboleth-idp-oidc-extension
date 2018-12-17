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

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import javax.annotation.Nonnull;

import org.geant.security.jwk.JWKCredential;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
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
 * 
 * TODO: Currently supports only RSA & EC families of encryption methods.
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
        if (JWEAlgorithm.Family.ASYMMETRIC.contains(encAlg)) {
            JWKCredential credential = (JWKCredential) params.getKeyTransportEncryptionCredential();
            EncryptionMethod encEnc = EncryptionMethod.parse(params.getDataEncryptionAlgorithm());
            log.debug("{} encrypting with key {} and params alg: {} enc: {}", getLogPrefix(), credential.getKid(),
                    encAlg.getName(), encEnc.getName());
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(encAlg, encEnc).contentType("JWT").build(), payload);
            try {
                if (JWEAlgorithm.Family.RSA.contains(encAlg)) {
                    jweObject.encrypt(new RSAEncrypter((RSAPublicKey) credential.getPublicKey()));
                } else {
                    jweObject.encrypt(new ECDHEncrypter((ECPublicKey) credential.getPublicKey()));
                }
                getOidcResponseContext().setProcessedToken(EncryptedJWT.parse(jweObject.serialize()));
                return;
            } catch (JOSEException | ParseException e) {
                log.error("{} Encryption failed {}", getLogPrefix(), e.getMessage());
            }
        }
        log.error("{} Encryption did not take place propably because of missing implementation support for algorithm",
                getLogPrefix());
        ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCRYPT);
    }

}