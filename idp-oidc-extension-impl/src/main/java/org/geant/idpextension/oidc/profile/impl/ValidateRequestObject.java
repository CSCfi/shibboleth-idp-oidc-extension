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

import java.text.ParseException;
import javax.annotation.Nonnull;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * Action that validates request object. Validated request object is stored to response context.
 */

// TODO checks for aud and iss?
/*
 * The Request Object MAY be signed or unsigned (plaintext). When it is plaintext, this is indicated by use of the none
 * algorithm [JWA] in the JOSE Header. If signed, the Request Object SHOULD contain the Claims iss (issuer) and aud
 * (audience) as members. The iss value SHOULD be the Client ID of the RP, unless it was signed by a different party
 * than the RP. The aud value SHOULD be or include the OP's Issuer Identifier URL.
 */
// TODO: Decryption

@SuppressWarnings("rawtypes")
public class ValidateRequestObject extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateRequestObject.class);

    /** Request Object. */
    JWT requestObject;

    /**
     * Constructor.
     */
    public ValidateRequestObject() {
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        super.doPreExecute(profileRequestContext);
        requestObject = getAuthenticationRequest().getRequestObject();
        if (requestObject == null) {
            log.debug("{} No request object, nothing to do", getLogPrefix());
            return false;
        }
        return true;
    }

    /**
     * Verify the request object signature.
     * 
     * @param reqObjSignAlgorithm algorithm of the jwt.
     * @return true if the jwt was verified.
     */
    private boolean verify(Algorithm reqObjSignAlgorithm) {
        if (reqObjSignAlgorithm.equals(Algorithm.NONE)) {
            return true;
        }
        JWSVerifier verifier = null;
        // RS or HS family?
        if (JWSAlgorithm.Family.HMAC_SHA.contains(reqObjSignAlgorithm)) {
            if (getMetadataContext().getClientInformation().getSecret() == null) {
                log.error("{} request object signed with {} but there is no client secret", getLogPrefix(),
                        reqObjSignAlgorithm.getName());
                return false;
            }
            try {
                verifier = new MACVerifier(getMetadataContext().getClientInformation().getSecret().getValue());
                if (!((SignedJWT) requestObject).verify(verifier)) {
                    log.error("{} request object signature verification failed", getLogPrefix());
                    return false;
                } else {
                    return true;
                }
            } catch (JOSEException e) {
                log.error("{} unable to verify request object signature {}", getLogPrefix(), e.getMessage());
                return false;
            }
        } else {
            JWKSet keySet = getMetadataContext().getClientInformation().getOIDCMetadata().getJWKSet();
            if (keySet == null) {
                log.error("{} request object signed with {} but there is no keyset ", getLogPrefix(),
                        reqObjSignAlgorithm.getName());
                return false;
            }
            for (JWK key : keySet.getKeys()) {
                if (!reqObjSignAlgorithm.equals(key.getAlgorithm())) {
                    continue;
                }
                if (KeyUse.ENCRYPTION.equals(key.getKeyUse())) {
                    continue;
                }
                if (JWSAlgorithm.Family.RSA.contains(reqObjSignAlgorithm)) {
                    try {
                        verifier = new RSASSAVerifier(((RSAKey) key).toRSAPublicKey());
                    } catch (JOSEException e) {
                        log.error("{} unable to verify request object signature {}", getLogPrefix(), e.getMessage());
                        return false;
                    }
                } else if (JWSAlgorithm.Family.EC.contains(reqObjSignAlgorithm)) {
                    try {
                        verifier = new ECDSAVerifier(((ECKey) key).toECPublicKey());
                    } catch (JOSEException e) {
                        log.error("{} unable to verify request object signature {}", getLogPrefix(), e.getMessage());
                        return false;
                    }
                }
                if (verifier == null) {
                    log.error("{} Unable to obtain verifier for {}", getLogPrefix(), reqObjSignAlgorithm.getName());
                    return false;
                }
                try {
                    if (((SignedJWT) requestObject).verify(verifier)) {
                        return true;
                    }
                } catch (IllegalStateException | JOSEException e) {
                    log.error("{} unable to verify request object signature {}", getLogPrefix(), e.getMessage());
                    return false;
                }
            }
        }
        return false;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        // Verify req object is signed with correct algorithm
        JWSAlgorithm regAlgorithm =
                getMetadataContext().getClientInformation().getOIDCMetadata().getRequestObjectJWSAlg();
        Algorithm reqObjSignAlgorithm = requestObject.getHeader().getAlgorithm();
        if (regAlgorithm != null && !regAlgorithm.equals(reqObjSignAlgorithm)) {
            log.error("{} request object signed with {} but the registered algorithm is ", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
            return;
        }
        // Verify signature
        if (!verify(reqObjSignAlgorithm)) {
            log.error("{} request object not verified by any of the available keys", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
            return;
        }
        // Validate client_id and response_type values
        try {
            if (requestObject.getJWTClaimsSet().getClaims().containsKey("client_id")
                    && !getAuthenticationRequest().getClientID()
                            .equals(new ClientID((String) requestObject.getJWTClaimsSet().getClaim("client_id")))) {
                log.error("{} client_id in request object not matching client_id request parameter", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
                return;
            }
            if (requestObject.getJWTClaimsSet().getClaims().containsKey("response_type")
                    && !getAuthenticationRequest().getResponseType().equals(new ResponseType(
                            ((String) requestObject.getJWTClaimsSet().getClaim("response_type")).split(" ")))) {
                log.error("{} response_type in request object not matching client_id request parameter", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
                return;
            }
        } catch (ParseException e) {
            log.error("{} Unable to parse request object {}", getLogPrefix(), e.getMessage());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
            return;
        }
    }
}