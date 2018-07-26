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

import javax.annotation.Nonnull;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import net.shibboleth.idp.session.IdPSession;
import net.shibboleth.idp.session.SessionResolver;
import net.shibboleth.idp.session.criterion.SessionIdCriterion;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.ParameterName;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Action that checks for "user presence" i.e. authenticated user has IdP Session unless original authentication request
 * had offline_access scope.
 */
@SuppressWarnings("rawtypes")
public class ValidateUserPresence extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateUserPresence.class);

    /** Looks up IdP sessions. */
    @Nonnull
    private final SessionResolver sessionResolver;

    /** Inactivity timeout for sessions in milliseconds. */
    @Duration
    @Positive
    private long sessionTimeout;

    /**
     * Constructor.
     *
     * @param resolver session resolver
     */
    public ValidateUserPresence(@Nonnull @ParameterName(name = "sessionResolver") final SessionResolver resolver) {
        sessionTimeout = 60 * 60 * 1000;
        sessionResolver = Constraint.isNotNull(resolver, "SessionResolver cannot be null");
    }

    /**
     * Set the session inactivity timeout policy in milliseconds, must be greater than zero.
     * 
     * @param timeout the policy to set
     */
    @Duration
    public void setSessionTimeout(@Duration @Positive final long timeout) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        sessionTimeout = Constraint.isGreaterThan(0, timeout, "Timeout must be greater than zero");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (getOidcResponseContext().getScope().contains(OIDCScopeValue.OFFLINE_ACCESS)) {
            log.debug("{} Authentication request had offline_access scope, user presence not required", getLogPrefix(),
                    getMetadataContext().getClientInformation().getID());
            return;
        }
        String id = getOidcResponseContext().getTokenClaimsSet().getSessionId();
        IdPSession session = null;
        try {
            session = sessionResolver.resolveSingle(new CriteriaSet(new SessionIdCriterion(id)));
        } catch (final ResolverException e) {
            log.error("{} IdPSession resolution error: {}", getLogPrefix(), e);
            // We let execution flow forward, Error event will be set.
        }
        if (session == null || session.getLastActivityInstant() + sessionTimeout < System.currentTimeMillis()) {
            log.error("{} Unable to validate user presence", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.ACCESS_DENIED);
        }

    }
}