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

package org.geant.idpextension.oidc.profile.context.navigate;

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
 * The value is host component of registered sector_identifier_uri or host
 * component of the registered redirect_uri in case there is no
 * sector_identifier_uri. In the latter case there must be only on registered
 * redirect_uri or null is returned.
 * 
 * <p>
 * If a specific setting is unavailable, a null value is returned.
 * </p>
 */
@SuppressWarnings("rawtypes")
public class SectorIdentifierLookupFunction extends AbstractIdentifiableInitializableComponent implements
        ContextDataLookupFunction<ProfileRequestContext, String> {

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
     * @param strategy
     *            lookup function to use
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        oidcMetadataContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCMetadata lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public String apply(@Nullable final ProfileRequestContext input) {
        String sectorIdentifier;
        OIDCMetadataContext ctx = oidcMetadataContextLookupStrategy.apply(input);
        if (ctx == null || ctx.getClientInformation() == null || ctx.getClientInformation().getOIDCMetadata() == null) {
            log.error("oidc metadata context not available");
            return null;
        }
        if (ctx.getClientInformation().getOIDCMetadata().getSectorIDURI() != null) {
            sectorIdentifier = ctx.getClientInformation().getOIDCMetadata().getSectorIDURI().getHost();
            log.debug("sector identifier by sector uri {}", sectorIdentifier);
        } else if (ctx.getClientInformation().getOIDCMetadata().getRedirectionURIs().size() > 0) {
            log.error("multiple registered redirection uris, unable to determine sector identifier");
            return null;
        } else {
            sectorIdentifier = ctx.getClientInformation().getOIDCMetadata().getRedirectionURI().getHost();
            log.debug("sector identifier by redirect uri {}", sectorIdentifier);
        }
        log.debug("5");
        return sectorIdentifier;
    }

}