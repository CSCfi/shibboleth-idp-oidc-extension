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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.net.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;

/**
 * A function that returns sector identifier obtained via a lookup function.
 * 
 * The value is host component of registered sector_identifier_uri or host component of the registered redirect_uri in
 * case there is no sector_identifier_uri. In the latter case there must be only on registered redirect_uri or null is
 * returned.
 * 
 * <p>
 * If a specific setting is unavailable, a null value is returned.
 * </p>
 */
@SuppressWarnings("rawtypes")
public class SectorIdentifierLookupFunction extends AbstractIdentifiableInitializableComponent
        implements ContextDataLookupFunction<ProfileRequestContext, String> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SectorIdentifierLookupFunction.class);

    /** Strategy function to lookup OIDC metadata context . */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /**
     * Constructor.
     */
    public SectorIdentifierLookupFunction() {
        oidcMetadataContextLookupStrategy = new DefaultOIDCMetadataContextLookupFunction();
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
    public String apply(@Nullable final ProfileRequestContext input) {
        if (input == null) {
            return null;
        }
        String sectorIdentifier = null;
        OIDCMetadataContext ctx = oidcMetadataContextLookupStrategy.apply(input);
        if (ctx == null || ctx.getClientInformation() == null || ctx.getClientInformation().getOIDCMetadata() == null) {
            log.warn("oidc metadata context not available");
        } else if (ctx.getClientInformation().getOIDCMetadata().getSectorIDURI() != null) {
            sectorIdentifier = ctx.getClientInformation().getOIDCMetadata().getSectorIDURI().getHost();
            log.debug("sector identifier by sector uri {}", sectorIdentifier);
        } else if (ctx.getClientInformation().getOIDCMetadata().getRedirectionURIs() != null
                && ctx.getClientInformation().getOIDCMetadata().getRedirectionURIs().size() > 1) {
            log.warn("multiple registered redirection uris, unable to determine sector identifier");
        } else {
            URI redirection = ctx.getClientInformation().getOIDCMetadata().getRedirectionURI();
            if (redirection != null) {
                sectorIdentifier = redirection.getHost();
                log.debug("sector identifier by redirect uri {}", sectorIdentifier);
            } else {
                log.warn("redirection uri not available");
            }
        }
        return sectorIdentifier;
    }

}