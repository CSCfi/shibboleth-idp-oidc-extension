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
import java.util.Iterator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.security.impl.OIDCSignatureValidationParameters;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that validates request object. Validated request object is stored to response context.
 */

@SuppressWarnings("rawtypes")
public class ValidateRequestObject extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateRequestObject.class);

    /*** The signature validation parameters. */
    @Nullable
    protected OIDCSignatureValidationParameters signatureValidationParameters;

    /**
     * Strategy used to locate the {@link SecurityParametersContext} to use for signing.
     */
    @Nonnull
    private Function<ProfileRequestContext, SecurityParametersContext> securityParametersLookupStrategy;

    /** Request Object. */
    private JWT requestObject;

    /** Constructor. */
    public ValidateRequestObject() {
        securityParametersLookupStrategy = new ChildContextLookup<>(SecurityParametersContext.class);
    }

    /**
     * Set the strategy used to locate the {@link SecurityParametersContext} to use.
     * 
     * @param strategy lookup strategy
     */
    public void setSecurityParametersLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, SecurityParametersContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        securityParametersLookupStrategy =
                Constraint.isNotNull(strategy, "SecurityParameterContext lookup strategy cannot be null");
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
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        // We let "none" to be used only if nothing else has been registered.
        if (requestObject instanceof PlainJWT
                && getMetadataContext().getClientInformation().getOIDCMetadata().getRequestObjectJWSAlg() != null
                && !"none".equals(getMetadataContext().getClientInformation().getOIDCMetadata().getRequestObjectJWSAlg()
                        .getName())) {
            log.error("{} Request object is not signed evethough registered alg is {}", getLogPrefix(),
                    getMetadataContext().getClientInformation().getOIDCMetadata().getRequestObjectJWSAlg().getName());
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
            return;
        }
        // Signature of signed request object must be verified
        if (!(requestObject instanceof PlainJWT)) {
            // Verify req object is signed with correct algorithm
            final SecurityParametersContext secParamCtx = securityParametersLookupStrategy.apply(profileRequestContext);
            if (secParamCtx == null) {
                log.error("{} No security parameters context is available", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
                return;
            }
            if (secParamCtx.getSignatureSigningParameters() == null
                    || !(secParamCtx.getSignatureSigningParameters() instanceof OIDCSignatureValidationParameters)) {
                log.debug("{} No signature validation credentials available", getLogPrefix());
                return;
            }
            signatureValidationParameters =
                    (OIDCSignatureValidationParameters) secParamCtx.getSignatureSigningParameters();
            Algorithm reqObjSignAlgorithm = requestObject.getHeader().getAlgorithm();
            if (!signatureValidationParameters.getSignatureAlgorithm().equals(reqObjSignAlgorithm.getName())) {
                log.error("{} Request object signed with algorithm {} but the registered algorithm is {}",
                        getLogPrefix(), reqObjSignAlgorithm.getName(),
                        signatureValidationParameters.getSignatureAlgorithm());
                ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
                return;
            }
            Iterator it = signatureValidationParameters.getValidationCredentials().iterator();
            boolean verified = false;
            while (it.hasNext()) {
                Credential credential = (Credential) it.next();
                JWSVerifier verifier = null;
                try {
                    if (JWSAlgorithm.Family.HMAC_SHA.contains(reqObjSignAlgorithm)) {
                        verifier = new MACVerifier(credential.getSecretKey());
                    }
                    if (JWSAlgorithm.Family.RSA.contains(reqObjSignAlgorithm)) {
                        verifier = new RSASSAVerifier((RSAPublicKey) credential.getPublicKey());
                    }
                    if (JWSAlgorithm.Family.EC.contains(reqObjSignAlgorithm)) {
                        verifier = new ECDSAVerifier((ECPublicKey) credential.getPublicKey());
                    }
                    if (verifier == null) {
                        log.error("{} No verifier for request object for alg {}", getLogPrefix(),
                                reqObjSignAlgorithm.getName());
                        ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
                    }
                    if (!((SignedJWT) requestObject).verify(verifier)) {
                        if (it.hasNext()) {
                            log.debug("{} Unable to validate request object with credential, picking next key",
                                    getLogPrefix());
                            continue;
                        } else {
                            log.error("{} Unable to validate request object with any of the credentials",
                                    getLogPrefix());
                            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
                            return;
                        }
                    }
                    verified = true;
                    break;
                } catch (JOSEException e) {
                    if (it.hasNext()) {
                        log.debug("{} Unable to validate request object with credential, {}, picking next key",
                                getLogPrefix(), e.getMessage());
                    } else {
                        log.error("{} Unable to validate request object with any of the credentials, {}",
                                getLogPrefix(), e.getMessage());
                        ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_REQUEST_OBJECT);
                        return;
                    }
                }
            }
            if (!verified) {
                // This is executed only if there was no credentials (which should not happen).
                log.error("{} Unable to validate request object signature", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_SEC_CFG);
                return;
            }

        }
        // Validate still client_id and response_type values
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
                log.error("{} response_type in request object not matching client_id request parameter",
                        getLogPrefix());
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