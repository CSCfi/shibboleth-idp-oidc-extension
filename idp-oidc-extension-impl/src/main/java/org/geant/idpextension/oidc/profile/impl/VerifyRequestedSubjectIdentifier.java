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
            return;
        }
        log.debug("{} Requested subject matched the generated subject {}", getLogPrefix(), generatedSubject);
    }

}