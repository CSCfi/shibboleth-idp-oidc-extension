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

import net.shibboleth.idp.authn.context.SubjectContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that creates an {@link SubjectContext} and attaches it to the current {@link ProfileRequestContext}. The
 * principal is set by the information provided by Authorization Code / Access Token.
 */
@SuppressWarnings("rawtypes")
public class InitializeSubjectContext extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeSubjectContext.class);

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        if (getOidcResponseContext().getTokenClaimsSet() == null) {
            log.error("{} user principal not resolved from token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        SubjectContext subCtx = profileRequestContext.getSubcontext(SubjectContext.class, true);
        subCtx.setPrincipalName(getOidcResponseContext().getTokenClaimsSet().getPrincipal());
        log.debug("{} Created subject context {} for user {}", getLogPrefix(), subCtx,
                getOidcResponseContext().getTokenClaimsSet().getPrincipal());
    }

}