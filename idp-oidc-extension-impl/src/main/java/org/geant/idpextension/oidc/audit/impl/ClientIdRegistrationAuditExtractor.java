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

package org.geant.idpextension.oidc.audit.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCRegistrationResponseContextLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Looks up the client ID value from the OIDC client registration response context.
 */
public class ClientIdRegistrationAuditExtractor implements Function<ProfileRequestContext, String> {

    /** Lookup strategy for the context to find the subject value from. */
    @Nonnull
    private final Function<ProfileRequestContext, OIDCClientRegistrationResponseContext> ctxLookupStrategy;

    public ClientIdRegistrationAuditExtractor() {
        this(new OIDCRegistrationResponseContextLookupFunction());
    }

    public ClientIdRegistrationAuditExtractor(
            final Function<ProfileRequestContext, OIDCClientRegistrationResponseContext> strategy) {
        ctxLookupStrategy =
                Constraint.isNotNull(strategy, "OIDCClientRegistrationResponseContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public String apply(@Nullable final ProfileRequestContext input) {
        final OIDCClientRegistrationResponseContext context = ctxLookupStrategy.apply(input);
        if (context != null) {
            return context.getClientId();
        }

        return null;
    }
}
