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

package org.geant.idpextension.oidc.profile.logic;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultOIDCMetadataContextLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.SubjectType;

/**
 * Function to decide on subject type. Subject type is located from client's registration data.
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
     * Set the lookup strategy to use to locate the {@link RelyingPartyContext}.
     * 
     * @param strategy lookup function to use
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
    }

    /**
     * Set the lookup strategy to use to locate the {@link OIDCMetadataContext}.
     * 
     * @param strategy lookup function to use
     */
    public void setOIDCMetadataContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        oidcMetadataContextLookupStrategy =
                Constraint.isNotNull(strategy, "OIDCMetadata lookup strategy cannot be null");
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
        return type == null ? SubjectType.PUBLIC : type;

    }

}