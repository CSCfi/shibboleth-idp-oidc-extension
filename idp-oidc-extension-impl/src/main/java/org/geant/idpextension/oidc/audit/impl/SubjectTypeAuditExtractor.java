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

package org.geant.idpextension.oidc.audit.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

import net.shibboleth.utilities.java.support.logic.Constraint;

/** {@link Function} that returns the type of the subject from {@link OIDCAuthenticationResponseContext}. */
public class SubjectTypeAuditExtractor implements Function<ProfileRequestContext, String> {

    /** Lookup strategy for the context to find the subject type from. */
    @Nonnull
    private final Function<ProfileRequestContext, OIDCAuthenticationResponseContext> ctxLookupStrategy;

    /**
     * Constructor.
     */
    public SubjectTypeAuditExtractor() {
        this(new OIDCAuthenticationResponseContextLookupFunction());
    }

    /**
     * Constructor.
     *
     * @param strategy lookup strategy for message
     */
    public SubjectTypeAuditExtractor(
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
            return context.getSubjectType();
        }

        return null;
    }

}