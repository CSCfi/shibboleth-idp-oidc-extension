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

import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.CurrentOrPreviousEventLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This action is extended by error response actions. Action reads an event from the configured {@link EventContext}
 * lookup strategy, constructs an OIDC error response message and attaches it as the outbound message.
 * 
 * @param <T> ErrorResponse implementation.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractBuildErrorResponseFromEvent<T extends ErrorResponse> extends AbstractProfileAction {
    
    /** Default value for the error code in the error response messages. */
    public static final String DEFAULT_ERROR_CODE = "invalid_request";
    
    /** Default value for the HTTP response status code in the HTTP responses. */
    public static final int DEFAULT_HTTP_STATUS_CODE = HTTPResponse.SC_BAD_REQUEST;

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractBuildErrorResponseFromEvent.class);

    /** Strategy function for access to {@link EventContext} to check. */
    @Nonnull
    private Function<ProfileRequestContext, EventContext> eventContextLookupStrategy;

    /** Map of eventIds to pre-configured error objects. */
    private Map<String, ErrorObject> mappedErrors;

    /** The status code for unmapped events. */
    private int defaultStatusCode;

    /** The code for unmapped events. */
    private String defaultCode;

    /** Constructor. */
    public AbstractBuildErrorResponseFromEvent() {
        eventContextLookupStrategy = new CurrentOrPreviousEventLookup();
        mappedErrors = new HashMap<>();
        defaultStatusCode = DEFAULT_HTTP_STATUS_CODE;
        defaultCode = DEFAULT_ERROR_CODE;
    }

    /**
     * Set the status code for unmapped events.
     * 
     * @param code The default status code for unmapped events.
     */
    public void setDefaultStatusCode(final int code) {
        defaultStatusCode = code;
    }

    /**
     * Set the code for unmapped events.
     * 
     * @param code The default status code for unmapped events.
     */
    public void setDefaultCode(@Nonnull final String code) {
        defaultCode = Constraint.isNotNull(code, "Default code cannot be null");
    }

    /**
     * Set lookup strategy for {@link EventContext} to check.
     * 
     * @param strategy lookup strategy
     */
    public void setEventContextLookupStrategy(@Nonnull final Function<ProfileRequestContext, EventContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        eventContextLookupStrategy = Constraint.isNotNull(strategy, "EventContext lookup strategy cannot be null");
    }

    /**
     * Set map of eventIds to pre-configured error objects.
     * 
     * @param errors map of eventIds to pre-configured error objects.
     */
    public void setMappedErrors(@Nonnull final Map<String, ErrorObject> errors) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        mappedErrors = Constraint.isNotNull(errors, "Mapped errors cannot be null");
    }

    /**
     * Method implemented by the extending class to create ErrorResponse.
     * 
     * @param error error object to build the response from.
     * @param profileRequestContext profile request context.
     * @return ErrorResponse
     */
    protected abstract T buildErrorResponse(ErrorObject error, ProfileRequestContext profileRequestContext);
    
    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (profileRequestContext.getOutboundMessageContext() == null) {
            log.error("{} No outbound message context initialized, nothing to do", getLogPrefix());
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final EventContext eventCtx = eventContextLookupStrategy.apply(profileRequestContext);
        if (eventCtx == null || eventCtx.getEvent() == null) {
            log.error("{} No event to be included in the response, nothing to do", getLogPrefix());
            return;
        }
        final String event = eventCtx.getEvent().toString();
        final ErrorObject error;
        if (mappedErrors.containsKey(event)) {
            log.debug("{} Found mapped event for {}", getLogPrefix(), event);
            error = mappedErrors.get(event);
        } else {
            log.debug("{} No mapped event found for {}, creating general {}", getLogPrefix(), event, defaultCode);
            error = new ErrorObject(defaultCode, eventCtx.getEvent().toString(), defaultStatusCode);
        }
        final ErrorResponse errorResponse = buildErrorResponse(error, profileRequestContext);
        if (errorResponse != null) {
            profileRequestContext.getOutboundMessageContext()
                    .setMessage(buildErrorResponse(error, profileRequestContext));
            log.debug("{} ErrorResponse successfully set as the outbound message", getLogPrefix());
        } else {
            log.debug("{} Error response not formed", getLogPrefix());
        }
    }
}
