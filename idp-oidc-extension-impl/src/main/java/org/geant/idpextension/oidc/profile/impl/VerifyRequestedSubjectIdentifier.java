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
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Action verifies that produced subject equals to requested subject if such exists.
 */
@SuppressWarnings("rawtypes")
public class VerifyRequestedSubjectIdentifier extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(VerifyRequestedSubjectIdentifier.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final String requestedSubject = getOidcResponseContext().getRequestedSubject();
        final String generatedSubject = getOidcResponseContext().getSubject();
        if (requestedSubject == null) {
            log.debug("{} No requested subject, nothing to do", getLogPrefix());
            return;
        }
        if (!requestedSubject.equals(generatedSubject)) {
            log.error("{} client requested for subject {}, the produced subject is {}, mismatch", getLogPrefix(),
                    requestedSubject, generatedSubject);
            ActionSupport.buildEvent(profileRequestContext, OidcEventIds.INVALID_SUBJECT);
        }
        log.debug("{} Requested subject matched the generated subject {}", getLogPrefix(), generatedSubject);
    }

}