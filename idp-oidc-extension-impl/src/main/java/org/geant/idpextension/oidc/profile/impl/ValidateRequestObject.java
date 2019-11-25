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

import java.text.ParseException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.geant.idpextension.oidc.security.impl.JWTSignatureValidationUtil;
import org.geant.idpextension.oidc.security.impl.OIDCSignatureValidationParameters;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action validates request object in response context.
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
            final String errorEventId = JWTSignatureValidationUtil.validateSignature(secParamCtx,
                    (SignedJWT) requestObject, OidcEventIds.INVALID_REQUEST_OBJECT);
            if (errorEventId != null) {
                ActionSupport.buildEvent(profileRequestContext, errorEventId);
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
                log.error("{} response_type in request object not matching response_type request parameter",
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