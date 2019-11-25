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

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** {@link Function} that returns the value of the subject from {@link OIDCAuthenticationResponseContext}. */
public class SubjectValueAuditExtractor implements Function<ProfileRequestContext, String> {

    /** Lookup strategy for the context to find the subject value from. */
    @Nonnull
    private final Function<ProfileRequestContext, OIDCAuthenticationResponseContext> ctxLookupStrategy;

    /**
     * Constructor.
     */
    public SubjectValueAuditExtractor() {
        this(new OIDCAuthenticationResponseContextLookupFunction());
    }

    /**
     * Constructor.
     *
     * @param strategy lookup strategy for message
     */
    public SubjectValueAuditExtractor(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseContext> strategy) {
        ctxLookupStrategy =
                Constraint.isNotNull(strategy, "OIDC authentication response context lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public String apply(@Nullable final ProfileRequestContext input) {
        final OIDCAuthenticationResponseContext context = ctxLookupStrategy.apply(input);
        if (context != null) {
            return context.getSubject();
        }

        return null;
    }

}