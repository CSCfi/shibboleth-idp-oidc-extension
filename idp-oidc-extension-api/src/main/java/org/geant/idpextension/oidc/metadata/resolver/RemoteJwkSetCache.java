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

package org.geant.idpextension.oidc.metadata.resolver;

import java.io.IOException;
import java.net.URI;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.http.client.HttpClient;
import org.geant.idpextension.oidc.metadata.support.RemoteJwkUtils;
import org.opensaml.security.httpclient.HttpClientSecurityParameters;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageCapabilitiesEx;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Stores fetched remote key set values for a desired period of time.
 */
public class RemoteJwkSetCache extends AbstractIdentifiableInitializableComponent {

    /** The context name in the {@link StorageService}. */
    public static final String CONTEXT_NAME = "oidcRemoteJwkSetContents";

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(RemoteJwkSetCache.class);

    /** Backing storage for the remote JWK set contents. */
    private StorageService storage;

    /** The {@link HttpClient} to use. */
    @NonnullAfterInit private HttpClient httpClient;
    
    /** HTTP client security parameters. */
    @Nullable private HttpClientSecurityParameters httpClientSecurityParameters;

    /**
     * Get the backing store for the remote JWK set contents.
     * 
     * @return the backing store.
     */
    @NonnullAfterInit
    public StorageService getStorage() {
        return storage;
    }

    /**
     * Set the backing store for the remote JWK set contents.
     * 
     * @param storageService backing store to use
     */
    public void setStorage(@Nonnull final StorageService storageService) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        storage = Constraint.isNotNull(storageService, "StorageService cannot be null");
        final StorageCapabilities caps = storage.getCapabilities();
        if (caps instanceof StorageCapabilitiesEx) {
            Constraint.isTrue(((StorageCapabilitiesEx) caps).isServerSide(), "StorageService cannot be client-side");
        }
    }

    /**
     * Set the {@link HttpClient} to use.
     * 
     * @param client client to use
     */
    public void setHttpClient(@Nonnull final HttpClient client) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClient = Constraint.isNotNull(client, "HttpClient cannot be null");
    }

    /**
     * Set the optional client security parameters.
     * 
     * @param params the new client security parameters
     */
    public void setHttpClientSecurityParameters(@Nullable final HttpClientSecurityParameters params) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        httpClientSecurityParameters = params;
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        if (storage == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }
        if (httpClient == null) {
            throw new ComponentInitializationException("HttpClient cannot be null");
        }
    }

    /**
     * Returns remote JWK set if found from the cache, otherwise fetches and stores it.
     * 
     * @param uri value to check
     * @param expires time (in milliseconds since beginning of epoch) for disposal of value from cache
     * 
     * @return JWK set, null if not found from the cache and cannot be fetched.
     */
    public JWKSet fetch(@Nonnull final URI uri, final long expires) {
        return fetch(CONTEXT_NAME, uri, expires);
    }

    /**
     * Returns remote JWK set if found from the cache, otherwise fetches and stores it.
     * 
     * @param context a context label to subdivide the cache
     * @param uri value to check
     * @param expires time (in milliseconds since beginning of epoch) for disposal of value from cache
     * 
     * @return JWK set, null if not found from the cache and cannot be fetched.
     */
    public JWKSet fetch(@Nonnull @NotEmpty final String context, @Nonnull final URI uri, final long expires) {
        final String key = uri.toString();

        final StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return null;
        }

        try {
            final StorageRecord<?> entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Value '{}' was not in the cache, fetching it", key);
                final JWKSet remoteJwkSet = RemoteJwkUtils.fetchRemoteJwkSet("RemoteJwkSetCache", uri, httpClient, 
                        httpClientSecurityParameters);
                if (remoteJwkSet != null && remoteJwkSet.getKeys() != null && !remoteJwkSet.getKeys().isEmpty()) {
                    storage.create(context, key, remoteJwkSet.toString(), expires);
                    return remoteJwkSet;
                } else {
                    log.warn("Could not find any remote keys from {}", key);
                }
            } else {
                final JWKSet cachedSet = JWKSet.parse(entry.getValue());
                log.debug("Cached value found and will be returned, expires at {}", entry.getExpiration());
                return cachedSet;
            }
        } catch (final IOException | java.text.ParseException e) {
            log.error("Exception reading/writing to storage service", e);
        }

        return null;
    }
}
