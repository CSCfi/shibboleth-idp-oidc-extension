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
package org.geant.idpextension.oidc.profile.logic;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.config.logic.PairwiseSubjectPredicate;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultOIDCMetadataContextLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.SubjectType;

/**
 * Function to select subject type derived from an entity's oidc metadata or
 * configuration preferences if not in metadata.
 * 
 */
@SuppressWarnings("rawtypes")
public class DefaultSubjectTypeStrategy implements Function<ProfileRequestContext, SubjectType> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(DefaultSubjectTypeStrategy.class);

    /** Strategy function to lookup OIDC metadata context . */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /**
     * Constructor.
     */
    public DefaultSubjectTypeStrategy() {
        oidcMetadataContextLookupStrategy = new DefaultOIDCMetadataContextLookupFunction();
    }

    /**
     * Set the lookup strategy to use to locate the {@link OIDCMetadataContext}.
     * 
     * @param strategy
     *            lookup function to use
     */
    public void setOIDCMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        oidcMetadataContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCMetadata lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public SubjectType apply(@Nullable final ProfileRequestContext input) {

        SubjectType type = null;
        OIDCMetadataContext ctx = oidcMetadataContextLookupStrategy.apply(input);
        if (ctx != null && ctx.getClientInformation() != null && ctx.getClientInformation().getOIDCMetadata() != null) {
            type = ctx.getClientInformation().getOIDCMetadata().getSubjectType();
        }
        if (type == null) {
            type = new PairwiseSubjectPredicate().apply(input) ? SubjectType.PAIRWISE : SubjectType.PUBLIC;
        }
        return type;
    }

}