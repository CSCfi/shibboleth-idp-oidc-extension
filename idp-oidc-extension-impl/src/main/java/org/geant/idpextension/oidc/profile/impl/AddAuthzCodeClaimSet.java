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

import java.util.Date;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.context.navigate.ResponderIdLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that creates a {@link JWTClaimsSet} object for forming Authorization
 * Code, and sets it to work context
 * {@link OIDCAuthenticationResponseContext#getAuthzCodeClaims()} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}. The claim set is
 * not created if the requested response type is "id_token".
 *
 */
@SuppressWarnings("rawtypes")
public class AddAuthzCodeClaimSet extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddAuthzCodeClaimSet.class);

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /** Authorization code expiration time, defaults to 10min */
    private long authCodeExp = 600000;

    /**
     * Constructor.
     */
    public AddAuthzCodeClaimSet() {
        issuerLookupStrategy = new ResponderIdLookupFunction();
    }

    /**
     * Set authorization code expiration time.
     * 
     * @param exp
     *            authorization code expiration time
     */
    public void setAuthCodeExp(long exp) {
        authCodeExp = exp;
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        // Authorization Code is formed unless implicit flow with response type only
        // "id_token" is used
        if (!getAuthenticationRequest().getResponseType().equals(new ResponseType(OIDCResponseTypeValue.ID_TOKEN))) {
            Date dateNow = new Date();
            getOidcResponseContext().setAuthzCodeClaims(new JWTClaimsSet.Builder()
                    .audience(getAuthenticationRequest().getClientID().getValue())
                    .subject(subjectCtx.getPrincipalName()).issuer(issuerLookupStrategy.apply(profileRequestContext))
                    .issueTime(dateNow).expirationTime(new Date(dateNow.getTime() + authCodeExp))
                    // TODO: scope and claims field values to constants
                    .claim("scope", getAuthenticationRequest().getScope().toArray())
                    .claim("claims", getAuthenticationRequest().getClaims() == null ? null
                            : getAuthenticationRequest().getClaims().toJSONObject())
                    .build());
            log.debug("{} Setting authz code claim set to response context {}", getLogPrefix(),
                    getOidcResponseContext().getAuthzCodeClaims().toJSONObject().toJSONString());
        }

    }

}