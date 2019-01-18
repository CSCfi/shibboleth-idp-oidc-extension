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

package org.geant.idpextension.oidc.storage;

import java.io.IOException;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.annotation.constraint.ThreadSafeAfterInit;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.apache.commons.codec.digest.DigestUtils;
import org.opensaml.storage.StorageCapabilities;
import org.opensaml.storage.StorageCapabilitiesEx;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.StorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores and checks for revocation entries.
 * 
 * <p>
 * This class is thread-safe and uses a synchronized method to prevent race conditions within the underlying store
 * (lacking an atomic "check and insert" operation).
 * </p>
 */
@ThreadSafeAfterInit
public class RevocationCache extends AbstractIdentifiableInitializableComponent {

    /** Logger. */
    private final Logger log = LoggerFactory.getLogger(RevocationCache.class);

    /** Backing storage for the replay cache. */
    private StorageService storage;

    /** Flag controlling behavior on storage failure. */
    private boolean strict;

    /** Lifetime of revocation entry. Default value: 6 hours */
    @Positive
    @Duration
    private long expires;

    /**
     * Constructor.
     */
    public RevocationCache() {
        expires = 6 * 60 * 60 * 1000;
    }

    /**
     * Set the revocation entry expiration.
     * 
     * @param entryExpiration lifetime of an revocation entry in milliseconds
     */
    @Duration
    public void setEntryExpiration(@Positive @Duration final long entryExpiration) {
        expires = Constraint.isGreaterThan(0, entryExpiration,
                "revocation cache entry expiration must be greater than 0");
    }

    /**
     * Get the backing store for the cache.
     * 
     * @return the backing store.
     */
    @NonnullAfterInit
    public StorageService getStorage() {
        return storage;
    }

    /**
     * Set the backing store for the cache.
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
     * Get the strictness flag.
     * 
     * @return true iff we should treat storage failures as a replay
     */
    public boolean isStrict() {
        return strict;
    }

    /**
     * Set the strictness flag.
     * 
     * @param flag true iff we should treat storage failures as a replay
     */
    public void setStrict(final boolean flag) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        strict = flag;
    }

    /** {@inheritDoc} */
    @Override
    public void doInitialize() throws ComponentInitializationException {
        if (storage == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }
    }

    /**
     * Returns true if the value is successfully revoked. If value has already been revoked, expiration is updated.
     * 
     * @param context a context label to subdivide the cache
     * @param s value to revoke
     * 
     * @return true if value has successfully been listed as revoked in the cache.
     */
    @SuppressWarnings("rawtypes")
    public synchronized boolean revoke(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s) {
        String key;

        StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return false;
        } else if (s.length() > caps.getKeySize()) {
            key = DigestUtils.sha1Hex(s);
        } else {
            key = s;
        }
        try {
            StorageRecord entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Entry '{}' of context '{}' is not yet on list of revoked entries,"
                        + " adding to cache with expiration time {}", key, context, expires);
                storage.create(context, key, "y", System.currentTimeMillis() + expires);
                return true;
            } else {
                storage.update(context, key, "y", System.currentTimeMillis() + expires);
                log.debug("Entry '{}' of context '{}' was already revoked, updating expiration", key, context);
                return true;
            }
        } catch (IOException e) {
            log.error("Exception reading/writing to storage service, returning {}", e, strict ? "failure" : "success");
            return !strict;
        }
    }

    /**
     * Returns false if the value has successfully been confirmed as not revoked.
     * 
     * @param context a context label to subdivide the cache
     * @param s value to revoke
     * 
     * @return false if the check value is not found in the cache
     */
    @SuppressWarnings("rawtypes")
    public synchronized boolean isRevoked(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String s) {
        String key;
        StorageCapabilities caps = storage.getCapabilities();
        if (context.length() > caps.getContextSize()) {
            log.error("context {} too long for StorageService (limit {})", context, caps.getContextSize());
            return true;
        } else if (s.length() > caps.getKeySize()) {
            key = DigestUtils.sha1Hex(s);
        } else {
            key = s;
        }

        try {
            StorageRecord entry = storage.read(context, key);
            if (entry == null) {
                log.debug("Entry '{}' is not revoked");
                return false;
            } else {
                log.debug("Entry '{}' is revoked", s);
                return true;
            }
        } catch (IOException e) {
            log.error("Exception reading/writing to storage service, returning {}", e, strict ? "failure" : "success");
            return !strict;
        }
    }

}