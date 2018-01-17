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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.metadata.resolver.RefreshableMetadataValueResolver;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.minidev.json.JSONObject;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * An extension to {@link FilesystemProviderMetadataResolver} that enables some of the claims to be dynamically
 * updated outside the file.
 */
public class DynamicFilesystemProviderMetadataResolver extends FilesystemProviderMetadataResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(DynamicFilesystemProviderMetadataResolver.class);
    
    /** The map of dynamic metadata value resolvers, key corresponding to the name of the metadata field. */
    private Map<String, RefreshableMetadataValueResolver> dynamicResolvers = new HashMap<>();

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public DynamicFilesystemProviderMetadataResolver(@Nonnull final File metadata) throws ResolverException {
        super(metadata);
    }

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * @param backgroundTaskTimer timer used to refresh metadata in the background
     * 
     * @throws ResolverException this exception is no longer thrown
     */
    public DynamicFilesystemProviderMetadataResolver(@Nullable final Timer backgroundTaskTimer, 
            @Nonnull final File metadata) throws ResolverException {
        super(backgroundTaskTimer, metadata);
    }
    
    /**
     * Set dynamic metadata value resolvers.
     * @param map What to set.
     */
    public void setDynamicValueResolvers(final Map<String, RefreshableMetadataValueResolver> map) {
        dynamicResolvers = Constraint.isNotNull(map, "The map of dynamic metadata resolvers cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected DateTime getMetadataUpdateTime() {
        DateTime updateTime = super.getMetadataUpdateTime();
        for (final String id : dynamicResolvers.keySet()) {
            final RefreshableMetadataValueResolver resolver = dynamicResolvers.get(id);
            if (resolver.getLastUpdate() == null) {
                return DateTime.now();
            }
            if (resolver.getLastUpdate().isAfter(updateTime)) {
                return resolver.getLastUpdate();
            }
        }
        return updateTime;
    }
    
    /** {@inheritDoc} */
    @Override
    protected OIDCProviderMetadata parse(byte[] bytes) throws ParseException {
        final OIDCProviderMetadata result = OIDCProviderMetadata.parse(JSONObjectUtils.parse(new String(bytes)));
        final JSONObject jsonResult = result.toJSONObject();
        for (final String key : dynamicResolvers.keySet()) {
            log.debug("Starting to resolve value for {}", key);
            final RefreshableMetadataValueResolver resolver = dynamicResolvers.get(key);
            try {
                resolver.refresh();
                final Object value = resolver.resolveSingle(null);
                if (value != null) {
                    jsonResult.put(key, value);
                    log.debug("The field {} updated to the result", key);
                }
            } catch (ResolverException e) {
                log.warn("Could not resolve a value for {̛}, ignoring it.", key, e);
            }
        }
        return OIDCProviderMetadata.parse(jsonResult);
    }
}
