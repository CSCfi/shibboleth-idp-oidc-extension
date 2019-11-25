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

import javax.annotation.Nonnull;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultAuthTimeLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;

/**
 * Action that sets authentication instant to work context {@link OIDCAuthenticationResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 */
@SuppressWarnings("rawtypes")
public class SetAuthenticationTimeToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetAuthenticationTimeToResponseContext.class);

    /** Strategy used to obtain the requested claims of request. */
    @Nonnull
    private Function<ProfileRequestContext, Long> authTimeLookupStrategy;

    /**
     * Constructor.
     */
    public SetAuthenticationTimeToResponseContext() {
        authTimeLookupStrategy = new DefaultAuthTimeLookupFunction();
    }

    /**
     * Set the strategy used to locate the authentication time.
     * 
     * @param strategy lookup strategy
     */
    public void setAuthTimeLookupStrategy(@Nonnull final Function<ProfileRequestContext, Long> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authTimeLookupStrategy =
                Constraint.isNotNull(strategy, "AuthTimeLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        Long value = authTimeLookupStrategy.apply(profileRequestContext);
        if (value == null) {
            log.error("{} No authentication instant available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        log.debug("{} Setting authentication time to {}", getLogPrefix(), value);
        getOidcResponseContext().setAuthTime(value);
    }

}