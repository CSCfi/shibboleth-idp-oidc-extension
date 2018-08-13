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

package org.geant.idpextension.oidc.metadata.resolver;

import java.io.IOException;
import java.net.URI;

import javax.annotation.Nonnull;

import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.util.EntityUtils;
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
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
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

    /** The builder for the {@link HttpClient}s. */
    private HttpClientBuilder clientBuilder;

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
     * Set the builder for the {@link HttpClient}s.
     * 
     * @param builder The builder for the {@link HttpClient}s.
     */
    public void setHttpClientBuilder(final HttpClientBuilder builder) {
        clientBuilder = Constraint.isNotNull(builder, "The HttpClientBuilder cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        if (storage == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }
        if (clientBuilder == null) {
            throw new ComponentInitializationException("HttpClientBuilder cannot be null");
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
                final JWKSet remoteJwkSet = fetchRemoteJwkSet(uri);
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

    /**
     * Fetches the JWK set from the given URI using a client built with the attached {@link HttpClientBuilder}.
     * 
     * @param uri The endpoint for the JWK set.
     * @return The JWK set fetched from the endpoint, or null if it couldn't be fetched.
     */
    protected JWKSet fetchRemoteJwkSet(final URI uri) {
        final HttpResponse response;
        try {
            final HttpUriRequest get = RequestBuilder.get().setUri(uri).build();
            response = clientBuilder.buildClient().execute(get);
        } catch (Exception e) {
            log.error("Could not get the JWK contents from {}", uri, e);
            return null;
        }
        if (response == null) {
            log.error("Could not get the JWK contents from {}", uri);
            return null;
        }
        final String output;
        try {
            output = EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (ParseException | IOException e) {
            log.error("Could not parse the JWK contents from {}", uri);
            return null;
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        log.trace("Fetched the following response body: {}", output);
        final JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(output);
        } catch (java.text.ParseException e) {
            log.error("Could not parse the contents from {}", uri, e);
            return null;
        }
        return jwkSet;
    }
}
