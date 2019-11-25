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
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedClaimsLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that sets requested claims to response context. For instance attribute filtering may use this information.
 */
@SuppressWarnings("rawtypes")
public class SetRequestedClaimsToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetRequestedClaimsToResponseContext.class);

    /** Strategy used to obtain the requested claims of request. */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsRequest> requestedClaimsLookupStrategy;

    /**
     * Constructor.
     */
    public SetRequestedClaimsToResponseContext() {
        requestedClaimsLookupStrategy = new DefaultRequestedClaimsLookupFunction();
    }

    /**
     * Set the strategy used to locate the requested claims of request.
     * 
     * @param strategy lookup strategy
     */
    public void
            setRequestedClaimsLookupStrategy(@Nonnull final Function<ProfileRequestContext, ClaimsRequest> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        requestedClaimsLookupStrategy =
                Constraint.isNotNull(strategy, "RequestedClaimsLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        getOidcResponseContext().setRequestedClaims(requestedClaimsLookupStrategy.apply(profileRequestContext));
    }
}