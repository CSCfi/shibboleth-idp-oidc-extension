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

package org.geant.idpextension.oidc.config;

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Profile configuration for the OpenID Connect core protocol userinfo endpoint.
 */
public class OIDCUserInfoConfiguration extends AbstractOIDCProfileConfiguration {

    /** OIDC base protocol URI. */
    public static final String PROTOCOL_URI = "http://openid.net/specs/openid-connect-core-1_0.html";

    /** ID for this profile configuration. */
    public static final String PROFILE_ID = "http://csc.fi/ns/profiles/oidc/userinfo";

    /** Predicate used to determine if the default value for generated subject is pairwise. Default returns false. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Predicate<ProfileRequestContext> pairwiseSubject;

    /**
     * Constructor.
     */
    public OIDCUserInfoConfiguration() {
        this(PROFILE_ID);
    }

    /**
     * Creates a new configuration instance.
     *
     * @param profileId Unique profile identifier.
     */
    public OIDCUserInfoConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        pairwiseSubject = Predicates.alwaysFalse();
    }

    /**
     * Get the predicate used to determine if default value for subject should be pairwise.
     * 
     * @return predicate to determine if subject should be pairwise.
     */
    @SuppressWarnings("rawtypes")
    @Nonnull
    public Predicate<ProfileRequestContext> getPairwiseSubject() {
        return pairwiseSubject;
    }

    /**
     * Set the predicate used to determine if default value for subject should be pairwise.
     * 
     * @param predicate predicate used to determine if subject should be pairwise
     */
    @SuppressWarnings("rawtypes")
    public void setPairwiseSubject(@Nonnull final Predicate<ProfileRequestContext> predicate) {
        pairwiseSubject = Constraint.isNotNull(predicate,
                "Predicate to determine if if subject should be pairwise cannot be null");
    }

}
