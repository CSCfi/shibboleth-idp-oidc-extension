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
import javax.annotation.Nullable;
import net.shibboleth.idp.saml.profile.config.navigate.SessionLifetimeLookupFunction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import org.geant.idpextension.oidc.messaging.context.OIDCResponseContext;
import org.joda.time.DateTime;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

/**
 * Action that sets id token expiration time to work context
 * {@link OIDCResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 */
@SuppressWarnings("rawtypes")
public class SetExpirationTimeToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetExpirationTimeToResponseContext.class);

    /** Strategy used to determine SessionNotOnOrAfter value to set. */
    @Nullable
    private Function<ProfileRequestContext, Long> sessionLifetimeLookupStrategy;

    /**
     * Constructor.
     */
    SetExpirationTimeToResponseContext() {
        sessionLifetimeLookupStrategy = new SessionLifetimeLookupFunction();
    }

    /**
     * Set the strategy used to locate the SessionNotOnOrAfter value to use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setSessionLifetimeLookupStrategy(@Nullable final Function<ProfileRequestContext, Long> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        sessionLifetimeLookupStrategy = strategy;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (sessionLifetimeLookupStrategy != null) {
            final Long lifetime = sessionLifetimeLookupStrategy.apply(profileRequestContext);
            if (lifetime != null && lifetime > 0) {
                long value = new DateTime().plus(lifetime).getMillis();
                log.debug("{} Setting exp to {}", getLogPrefix(), value);
                getOidcResponseContext().setExp(value);
            }
        }
    }

}