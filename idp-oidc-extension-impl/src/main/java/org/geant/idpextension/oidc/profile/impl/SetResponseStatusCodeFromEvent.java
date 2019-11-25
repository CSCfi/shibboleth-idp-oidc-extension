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
