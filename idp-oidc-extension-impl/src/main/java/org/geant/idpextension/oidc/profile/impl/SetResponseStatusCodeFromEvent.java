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

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;

import org.apache.http.HttpStatus;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.CurrentOrPreviousEventLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This action reads an event from the configured {@link EventContext} lookup strategy and sets the status code for
 * {@link HttpServletResponse} according to the attached configuration.
 */
@SuppressWarnings("rawtypes")
public class SetResponseStatusCodeFromEvent extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SetResponseStatusCodeFromEvent.class);
    
    /** Strategy function for access to {@link EventContext} to check. */
    @Nonnull private Function<ProfileRequestContext,EventContext> eventContextLookupStrategy;
    
    /** Map of eventIds to status codes. */
    private Map<String, Integer> mappedErrors;
    
    /** The status code for unmapped events. */
    private int defaultCode;
    
    /** Constructor. */
    public SetResponseStatusCodeFromEvent() {
        eventContextLookupStrategy = new CurrentOrPreviousEventLookup();
        mappedErrors = new HashMap<>();
        defaultCode = HttpStatus.SC_INTERNAL_SERVER_ERROR;
    }

    /**
     * Set lookup strategy for {@link EventContext} to check.
     * 
     * @param strategy  lookup strategy
     */
    public void setEventContextLookupStrategy(@Nonnull final Function<ProfileRequestContext,EventContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        eventContextLookupStrategy = Constraint.isNotNull(strategy, "EventContext lookup strategy cannot be null");
    }
    
    /**
     * Set the status code for unmapped events.
     * 
     * @param code The status code for unmapped events.
     */
    public void setDefaultCode(final int code) {
        defaultCode = code;
    }
    
    /**
     * Set map of eventIds to status codes.
     * 
     * @param errors map of eventIds to status codes.
     */
    public void setMappedErrors(@Nonnull final Map<String, Integer> errors) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        mappedErrors = Constraint.isNotNull(errors, "Mapped errors cannot be null");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final EventContext eventCtx = eventContextLookupStrategy.apply(profileRequestContext);
        if (eventCtx == null || eventCtx.getEvent() == null) {
            log.error("{} No event to be included in the response, nothing to do", getLogPrefix());
            return;
        }
        final String event = eventCtx.getEvent().toString();
        if (mappedErrors.containsKey(event)) {
            log.debug("{} Found mapped event for {}", getLogPrefix(), event);
            getHttpServletResponse().setStatus(mappedErrors.get(event));
        } else {
            log.debug("{} No mapping found for {}, default status code {} set", getLogPrefix(), event, defaultCode);
            getHttpServletResponse().setStatus(defaultCode);
        }
    }
}
