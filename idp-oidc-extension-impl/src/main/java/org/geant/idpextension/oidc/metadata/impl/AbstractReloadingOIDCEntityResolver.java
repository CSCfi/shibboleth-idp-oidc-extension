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

import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import javax.annotation.Nullable;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.chrono.ISOChronology;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;

import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * Based on {@link org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver}.
 */
public abstract class AbstractReloadingOIDCEntityResolver<Key extends Identifier, Value> 
    extends AbstractOIDCEntityResolver<Key, Value> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractReloadingOIDCEntityResolver.class);
    
    /** Timer used to schedule background metadata update tasks. */
    private Timer taskTimer;
    
    /** Whether we created our own task timer during object construction. */
    private boolean createdOwnTaskTimer;
        
    /** Current task to refresh metadata. */
    private RefreshMetadataTask refreshMetadataTask;
    
    /**
     * Refresh interval used when metadata does not contain any validUntil or cacheDuration information. Default value:
     * 14400000ms
     */
    @Duration @Positive private long maxRefreshDelay = 14400000;

    /** Floor, in milliseconds, for the refresh interval. Default value: 300000ms */
    @Duration @Positive private long minRefreshDelay = 300000;

    /** Last time the metadata was updated. */
    private DateTime lastUpdate;

    /** Last time a refresh cycle occurred. */
    private DateTime lastRefresh;

    /** Next time a refresh cycle will occur. */
    private DateTime nextRefresh;

    /** Constructor. */
    protected AbstractReloadingOIDCEntityResolver() {
        this(null);
    }

    /**
     * Constructor.
     * 
     * @param backgroundTaskTimer time used to schedule background refresh tasks
     */
    protected AbstractReloadingOIDCEntityResolver(@Nullable final Timer backgroundTaskTimer) {
        super();
        
        if (backgroundTaskTimer == null) {
            taskTimer = new Timer(true);
            createdOwnTaskTimer = true;
        } else {
            taskTimer = backgroundTaskTimer;
        }
    }

    protected void initOIDCResolver() throws ComponentInitializationException {
        super.initOIDCResolver();
        try {
            refresh();
        } catch (ResolverException e) {
            log.error("Could not refresh the entity information", e);
            throw new ComponentInitializationException("Could not refresh the entity information", e);
        }
    }

    /** {@inheritDoc} */
    @Nullable public DateTime getLastUpdate() {
        return lastUpdate;
    }

    /** {@inheritDoc} */
    @Nullable public DateTime getLastRefresh() {
        return lastRefresh;
    }
    
    /**
     * Sets the minimum amount of time, in milliseconds, between refreshes.
     * 
     * @param delay minimum amount of time, in milliseconds, between refreshes
     */
    @Duration public void setMinRefreshDelay(@Duration @Positive final long delay) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        if (delay < 0) {
            throw new IllegalArgumentException("Minimum refresh delay must be greater than 0");
        }
        minRefreshDelay = delay;
    }
    
    /**
     * Sets the maximum amount of time, in milliseconds, between refresh intervals.
     * 
     * @param delay maximum amount of time, in milliseconds, between refresh intervals
     */
    @Duration public void setMaxRefreshDelay(@Duration @Positive final long delay) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        
        if (delay < 0) {
            throw new IllegalArgumentException("Maximum refresh delay must be greater than 0");
        }
        maxRefreshDelay = delay;
    }
    
    /**
     * Refreshes the metadata from its source.
     * 
     * @throws ResolverException thrown is there is a problem retrieving and processing the metadata
     */
    public synchronized void refresh() throws ResolverException {
        final DateTime now = new DateTime(ISOChronology.getInstanceUTC());
        final String mdId = getMetadataIdentifier();

        long refreshDelay = 0;
        
        log.debug("Beginning refresh of metadata from '{}'", mdId);
        try {
            byte[] mdBytes = fetchMetadata();
            if (mdBytes == null) {
                log.debug("Metadata from '{}' has not changed since last refresh", mdId);
            } else {
                log.debug("Processing new metadata from '{}'", mdId);
                final Value information = parse(mdBytes);
                final Key id = getKey(information);
                log.info("Parsed entity information for {}", id);
                final JsonBackingStore newBackingStore = new JsonBackingStore();
                List<Value> allInformation = new ArrayList<>();
                allInformation.add(information);
                newBackingStore.getIndexedInformation().put(id, allInformation);
                newBackingStore.getOrderedInformation().add(information);
                setBackingStore(newBackingStore);
                lastUpdate = now;
            }
        } catch (Throwable t) {
            log.error("Error occurred while attempting to refresh metadata from '" + mdId + "'", t);
            refreshDelay = minRefreshDelay;
            if (t instanceof Exception) {
                throw new ResolverException((Exception) t);
            } else {
                throw new ResolverException(String.format("Saw an error of type '%s' with message '%s'", 
                        t.getClass().getName(), t.getMessage()));
            }
        } finally {
            scheduleNextRefresh(refreshDelay);
            lastRefresh = now;
        }
    }
    
    /**
     * Schedules the next refresh. If the given delay is 0, then {@link maxRefreshDelay} is used.
     * @param delay The delay before the next refresh.
     */
    protected void scheduleNextRefresh(final long delay) {
        refreshMetadataTask = new RefreshMetadataTask();
        long refreshDelay = delay;
        if (delay == 0) {
            refreshDelay = maxRefreshDelay;
        }
        nextRefresh = new DateTime(ISOChronology.getInstanceUTC()).plus(refreshDelay);
        final long nextRefreshDelay = nextRefresh.getMillis() - System.currentTimeMillis();

        taskTimer.schedule(refreshMetadataTask, nextRefreshDelay);
        log.info("Next refresh cycle for metadata provider '{}' will occur on '{}' ('{}' local time)",
                new Object[] {getMetadataIdentifier(), nextRefresh, 
                        nextRefresh.toDateTime(DateTimeZone.getDefault()),});
    }
    
    /**
     * Parses an entity from the byte array.
     * 
     * @param bytes The encoded entity.
     * @return The parsed entity.
     */
    protected abstract Value parse(final byte[] bytes) throws ParseException;
    
    /**
     * Gets the identifier for the given entity.
     * 
     * @param value The entity whose identifier will be returned.
     * @return The identifier for the given entity.
     */
    protected abstract Key getKey(final Value value);
    
    /**
     * Gets an identifier which may be used to distinguish this metadata in logging statements.
     * 
     * @return identifier which may be used to distinguish this metadata in logging statements
     */
    protected abstract String getMetadataIdentifier();

    /**
     * Fetches metadata from a source.
     * 
     * @return the fetched metadata, or null if the metadata is known not to have changed since the last retrieval
     * 
     * @throws ResolverException thrown if there is a problem fetching the metadata
     */
    protected abstract byte[] fetchMetadata() throws ResolverException;
    
    /** Background task that refreshes metadata. */
    private class RefreshMetadataTask extends TimerTask {

        /** {@inheritDoc} */
        @Override
        public void run() {
            try {
                if (!isInitialized()) {
                    // just in case the metadata provider was destroyed before this task runs
                    return;
                }
                
                refresh();
            } catch (ResolverException e) {
                // nothing to do, error message already logged by refreshMetadata()
                return;
            }
        }
    }
}