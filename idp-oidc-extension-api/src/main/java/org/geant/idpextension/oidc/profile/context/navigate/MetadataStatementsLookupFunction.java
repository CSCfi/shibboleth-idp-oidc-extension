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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A function that returns metadata_statements (oidcfed) obtained via a lookup function.
 * 
 * <p>
 * If a specific setting is unavailable, a null value is returned.
 * </p>
 */
@SuppressWarnings("rawtypes")
public class MetadataStatementsLookupFunction extends AbstractIdentifiableInitializableComponent implements
    ContextDataLookupFunction<ProfileRequestContext, Map<String, String>> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(MetadataStatementsLookupFunction.class);

    /** Strategy function to lookup OIDC metadata context . */
    @Nonnull
    private Function<ProfileRequestContext, OIDCMetadataContext> oidcMetadataContextLookupStrategy;

    /**
     * Constructor.
     */
    public MetadataStatementsLookupFunction() {
        oidcMetadataContextLookupStrategy = new DefaultOIDCMetadataContextLookupFunction();
    }

    /**
     * Set the lookup strategy to use to locate the {@link OIDCMetadataContext}.
     * 
     * @param strategy The lookup function to use.
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCMetadataContext> strategy) {
        oidcMetadataContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCMetadata lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Map<String, String> apply(@Nullable final ProfileRequestContext input) {
        final OIDCMetadataContext ctx = oidcMetadataContextLookupStrategy.apply(input);
        if (ctx == null || ctx.getClientInformation() == null 
                || ctx.getClientInformation().getOIDCMetadata() == null) {
            log.error("The OIDC metadata context not available");
            return null;
        }
        final OIDCClientMetadata metadata = ctx.getClientInformation().getOIDCMetadata();
        final Object rawStatements = metadata.getCustomField("metadata_statements");
        if (rawStatements != null && rawStatements instanceof JSONObject) {
            final JSONObject statements = (JSONObject) rawStatements;
            final Map<String, String> parsedStatements = new HashMap<>();
            final Iterator<Map.Entry<String, Object>> iterator = statements.entrySet().iterator();
            while (iterator.hasNext()) {
                final Map.Entry<String, Object> entry = iterator.next();
                final String key = entry.getKey();
                final Object value = entry.getValue();
                if (value != null && value instanceof String) {
                    log.debug("Adding a metadata statement for federation {}", key);
                    parsedStatements.put(key, (String) value);
                } else {
                    log.debug("Ignoring unexpected format for value {}", value);
                }
            }
            return parsedStatements;
        }
        log.debug("Could not find metadata_statements from the metadata");
        return null;
    }

}