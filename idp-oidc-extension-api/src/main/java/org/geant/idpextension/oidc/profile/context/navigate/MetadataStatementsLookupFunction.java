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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.navigate.OIDCClientRegistrationRequestMetadataLookupFunction;
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
    private Function<ProfileRequestContext, OIDCClientMetadata> oidcMetadataLookupStrategy;

    /**
     * Constructor.
     */
    public MetadataStatementsLookupFunction() {
        oidcMetadataLookupStrategy = new OIDCClientRegistrationRequestMetadataLookupFunction();
    }

    /**
     * Set the lookup strategy to use to locate the {@link OIDCClientMetadata}.
     * 
     * @param strategy The lookup function to use.
     */
    public void setMetadataLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCClientMetadata> strategy) {
        oidcMetadataLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCMetadata lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Map<String, String> apply(@Nullable final ProfileRequestContext input) {
        final OIDCClientMetadata metadata = oidcMetadataLookupStrategy.apply(input);
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