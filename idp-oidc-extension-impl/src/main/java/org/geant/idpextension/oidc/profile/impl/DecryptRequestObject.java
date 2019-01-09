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

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Iterator;

import javax.annotation.Nonnull;
import javax.crypto.SecretKey;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.security.impl.OIDCDecryptionParameters;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.AESDecrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action decrypts request object if it is encrypted. Decrypted object is updated to response context.
 */

@SuppressWarnings("rawtypes")
public class DecryptRequestObject extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(DecryptRequestObject.class);

    /** Strategy used to look up the {@link EncryptionContext} to store parameters in. */
    @Nonnull
    private Function<ProfileRequestContext, EncryptionContext> encryptionContextLookupStrategy;

    /** Decryption parameters for decrypting payload. */
    private OIDCDecryptionParameters params;

    /** Request Object. */
    JWT requestObject;

    /**
     * Constructor.
     */
    public DecryptRequestObject() {
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
        requestObject = getOidcResponseContext().getRequestObject();
        if (requestObject == null) {
            log.debug("{} No request object, nothing to do", getLogPrefix());
            return false;
        }
        if (!(requestObject instanceof EncryptedJWT)) {
            log.debug("{} Request object not encrypted, nothing to do", getLogPrefix());
            return false;
        }
        // OIDC decryption parameters are set to stock shibboleth context as
        // EncryptionContex#getAttributeEncryptionParameters()
        final EncryptionContext encryptCtx = encryptionContextLookupStrategy.apply(profileRequestContext);
        if (encryptCtx == null
                || !(encryptCtx.getAttributeEncryptionParameters() instanceof OIDCDecryptionParameters)) {
            log.error(
                    "{} Encrypted request object but no EncryptionContext/OIDCDecryptionParameters parameters available",
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
            return false;
        }
        params = (OIDCDecryptionParameters) encryptCtx.getAttributeEncryptionParameters();
        return true;
    }

    /**
     * Decrypt request object.
     * 
     * @param requestObject request object to decrypt.
     * @return Decrypted request object. Null if decrypting failed.
     */
    private JWT decryptRequestObject(EncryptedJWT requestObject) {
        if (!requestObject.getHeader().getAlgorithm().getName().equals(params.getKeyTransportEncryptionAlgorithm())) {
            log.error("Request object alg {} not matching expected {}",
                    requestObject.getHeader().getAlgorithm().getName(), params.getKeyTransportEncryptionAlgorithm());
            return null;
        }
        if (!requestObject.getHeader().getEncryptionMethod().getName().equals(params.getDataEncryptionAlgorithm())) {
            log.error("Request object enc {} not matching expected {}",
                    requestObject.getHeader().getEncryptionMethod().getName(), params.getDataEncryptionAlgorithm());
            return null;
        }
        JWEAlgorithm encAlg = requestObject.getHeader().getAlgorithm();
        Iterator it = params.getKeyTransportDecryptionCredentials().iterator();
        while (it.hasNext()) {
            Credential credential = (Credential) it.next();
            JWEDecrypter decrypter = null;
            try {
                if (JWEAlgorithm.Family.RSA.contains(encAlg)) {
                    decrypter = new RSADecrypter((PrivateKey) credential.getPrivateKey());
                }
                if (JWEAlgorithm.Family.ECDH_ES.contains(encAlg)) {
                    decrypter = new ECDHDecrypter((ECPrivateKey) credential.getPrivateKey());
                }
                if (JWEAlgorithm.Family.AES_GCM_KW.contains(encAlg) || JWEAlgorithm.Family.AES_KW.contains(encAlg)) {
                    decrypter = new AESDecrypter((SecretKey) credential.getSecretKey());
                }
                if (decrypter == null) {
                    log.error("No decrypter for request object for encAlg {}",
                            requestObject.getHeader().getEncryptionMethod().getName());
                    return null;
                }
                requestObject.decrypt(decrypter);
                return JWTParser.parse(requestObject.getPayload().toString());
            } catch (JOSEException | ParseException e) {
                if (it.hasNext()) {
                    log.debug("Unable to decrypt request object with credential, {}, picking next key", e.getMessage());
                } else {
                    log.error("Unable to decrypt request object with credential, {}", e.getMessage());
                    return null;
                }
            }
        }
        // Should never come here
        return null;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        requestObject = decryptRequestObject((EncryptedJWT) requestObject);
        if (requestObject == null) {
            log.error("{} Unable to decrypt request object", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
            return;
        }
        // Let's update decrypted request object back to response context
        getOidcResponseContext().setRequestObject(requestObject);
        log.debug("{} Request object decrypted as {}", getLogPrefix(),
                getOidcResponseContext().getRequestObject().serialize());
    }
}