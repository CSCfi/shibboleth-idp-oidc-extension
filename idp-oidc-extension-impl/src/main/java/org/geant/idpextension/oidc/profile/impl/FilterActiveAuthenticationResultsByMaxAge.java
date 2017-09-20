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

import java.util.Iterator;
import java.util.Map;
import javax.annotation.Nonnull;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that removed active results from {@link AuthenticationContext} if
 * they are older than max age parameter expects.
 * 
 */
@SuppressWarnings("rawtypes")
public class FilterActiveAuthenticationResultsByMaxAge extends AbstractOIDCAuthenticationRequestAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(FilterActiveAuthenticationResultsByMaxAge.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        int maxAge = getAuthenticationRequest().getMaxAge();
        log.debug("{} Filtering active results by max_age parameter {}", getLogPrefix(), maxAge);
        if (maxAge < 0) {
            log.debug("{} max_age is not set, nothing to do", getLogPrefix());
            return;
        }
        final AuthenticationContext authnCtx = profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authnCtx == null) {
            log.error("{} Unable to locate authentication context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return;
        }
        Map<String, AuthenticationResult> activeResults = authnCtx.getActiveResults();
        Iterator<Map.Entry<String, AuthenticationResult>> iter = activeResults.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry<String, AuthenticationResult> entry = iter.next();
            if (entry.getValue().getAuthenticationInstant() + (maxAge * 1000) < System.currentTimeMillis()) {
                log.debug("{} removing active result having authentication instant {}", getLogPrefix(), entry
                        .getValue().getAuthenticationInstant());
                iter.remove();
            }
        }
    }

}