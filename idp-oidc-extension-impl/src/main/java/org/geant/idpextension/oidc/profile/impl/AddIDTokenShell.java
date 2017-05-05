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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.messaging.context.OIDCResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Action that creates a {@link IDTokenClaimsSe} object shell , and sets it to
 * work context {@link OIDCResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 */
@SuppressWarnings("rawtypes")
public class AddIDTokenShell extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddIDTokenShell.class);

    /** Strategy used to obtain the response issuer value. */
    @Nullable
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** EntityID to populate into Issuer element. */
    @Nullable
    private String issuerId;

    /** oidc response context. */
    private OIDCResponseContext oidcResponseContext;

    /** OIDC Authentication request. */
    private AuthenticationRequest request;

    /** Authentication result. */
    AuthenticationResult authResult;

    /** Subject context. */
    SubjectContext subjectCtx;

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
    @SuppressWarnings({ "unchecked" })
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final MessageContext outboundMessageCtx = profileRequestContext.getOutboundMessageContext();
        if (outboundMessageCtx == null) {
            log.debug("{} No outbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof AuthenticationRequest)) {
            log.error("{} No inbound message", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        request = (AuthenticationRequest) message;
        oidcResponseContext = outboundMessageCtx.getSubcontext(OIDCResponseContext.class, false);
        if (oidcResponseContext == null) {
            log.debug("{} No oidc response context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        issuerId = issuerLookupStrategy.apply(profileRequestContext);
        AuthenticationContext authCtx = profileRequestContext.getSubcontext(AuthenticationContext.class, false);
        if (authCtx == null) {
            log.debug("{} No authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        authResult = authCtx.getAuthenticationResult();
        if (authResult == null) {
            log.debug("{} No authentication result", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.debug("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("Initializing id token");
        List<Audience> aud = new ArrayList<Audience>();
        /**
         * TODO: We create the id token in very simple hard coded way here.
         * Needs to be studied what will come from the configurations.
         */
        // TODO: rp as audience is obvious but should we support multiple
        // audience?
        aud.add(new Audience(request.getClientID().getValue()));
        Issuer iss = new Issuer(issuerId);
        // TODO: expiration time configuration
        Calendar calExp = Calendar.getInstance();
        calExp.add(Calendar.SECOND, 180);
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(iss, new Subject(subjectCtx.getPrincipalName()), aud,
                calExp.getTime(), new Date(authResult.getAuthenticationInstant()));
        log.debug("{} Setting id token shell to response context {}", getLogPrefix(), idToken.toJSONObject()
                .toJSONString());
        oidcResponseContext.setIDToken(idToken);
    }

}