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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.id.Identifier;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A base class for {@link Resolver}s used for resolving entities containing identifiers based on {@link Identifier}. 
 *
 * @param <Key> The identifier type in the backing store.
 * @param <Value> The entity type in the backing store.
 */
public abstract class AbstractOIDCEntityResolver<Key extends Identifier, Value> 
    extends AbstractIdentifiableInitializableComponent {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractOIDCEntityResolver.class);
    
    /** Backing store for runtime JSON data. */
    private JsonBackingStore jsonBackingStore;
    
    /** {@inheritDoc} */
    @Override protected final void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        try {
            initOIDCResolver();
        } catch (ComponentInitializationException e) {
            log.error("OIDC metadata provider failed to properly initialize", e);
        }
    }
    
    /**
     * Initializes this resolver by creating a new backing store.
     * @throws ComponentInitializationException
     */
    protected void initOIDCResolver() throws ComponentInitializationException {
        jsonBackingStore = createNewBackingStore();
    }

    /**
     * Get list of information matching a given identifier.
     * 
     * @param identifier identifier to lookup
     * @return a list of information
     * @throws ResolverException if an error occurs
     */
    @Nonnull @NonnullElements protected List<Value> lookupIdentifier(
            @Nonnull @NotEmpty final Key identifier)
            throws ResolverException {
        if (!isInitialized()) {
            throw new ResolverException("Metadata resolver has not been initialized");
        }

        if (identifier == null || Strings.isNullOrEmpty(identifier.getValue())) {
            log.debug("Identifier was null or empty, skipping search for it");
            return Collections.emptyList();
        }

        List<Value> allInformation = lookupIndexedIdentifier(identifier);
        if (allInformation.isEmpty()) {
            log.debug("Backing store does not contain any information with the ID: {}", identifier);
            return allInformation;
        }
        return allInformation;
    }

    /**
     * Lookup the specified identifier from the index. The returned list will be a copy of what is stored in the 
     * backing index, and is safe to be manipulated by callers.
     * 
     * @param identifier the identifier to lookup
     * 
     * @return list copy of indexed identifiers, may be empty, will never be null
     */
    @Nonnull @NonnullElements protected List<Value> lookupIndexedIdentifier(
            @Nonnull @NotEmpty final Key identifier) {
        List<Value> allInformation = getBackingStore().getIndexedInformation().get(identifier);
        if (allInformation != null) {
            return new ArrayList<>(allInformation);
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Pre-process the specified entity descriptor, updating the specified entity backing store instance as necessary.
     * 
     * @param entityDescriptor the target entity descriptor to process
     * @param backingStore the backing store instance to update
     */
    protected void preProcessEntityDescriptor(@Nonnull final Value entityDescriptor, @Nonnull final Key key,
            @Nonnull final JsonBackingStore backingStore) {

        backingStore.getOrderedInformation().add(entityDescriptor);
        indexEntityDescriptor(entityDescriptor, key, backingStore);
    }
    
    /**
     * Remove from the backing store all metadata for the entity with the given identifier.
     * 
     * @param identifier the identifier of the metadata to remove
     * @param backingStore the backing store instance to update
     */
    protected void removeByIdentifier(@Nonnull final Key identifier, @Nonnull final JsonBackingStore backingStore) {
        final Map<Key, List<Value>> indexedDescriptors = backingStore.getIndexedInformation();
        final List<Value> descriptors = indexedDescriptors.get(identifier);
        if (descriptors != null) {
            backingStore.getOrderedInformation().removeAll(descriptors);
        }
        indexedDescriptors.remove(identifier);
    }

    /**
     * Index the specified entity descriptor, updating the specified entity backing store instance as necessary.
     * 
     * @param entityDescriptor the target entity descriptor to process
     * @param backingStore the backing store instance to update
     */
    protected void indexEntityDescriptor(@Nonnull final Value entityDescriptor, @Nonnull final Key key,
            @Nonnull final JsonBackingStore backingStore) {

        List<Value> entities = backingStore.getIndexedInformation().get(key);
        if (entities == null) {
            entities = new ArrayList<>();
            backingStore.getIndexedInformation().put(key, entities);
        } else if (!entities.isEmpty()) {
            log.warn("Detected duplicate object for key: {}", key);
        }
        entities.add(entityDescriptor);
    }

    
    /**
     * Create a new backing store instance for entity data. Subclasses may override to return a more
     * specialized subclass type. Note this method does not make the returned backing store the effective one in use.
     * The caller is responsible for calling {@link #setBackingStore(JsonBackingStore)} to make it the effective
     * instance in use.
     * 
     * @return the new backing store instance
     */
    @Nonnull protected JsonBackingStore createNewBackingStore() {
        return new JsonBackingStore();
    }

    /**
     * Get the entity backing store currently in use by the metadata resolver.
     * 
     * @return the current effective entity backing store
     */
    @Nonnull protected JsonBackingStore getBackingStore() {
        return jsonBackingStore;
    }

    /**
     * Set the entity backing store currently in use by the metadata resolver.
     * 
     * @param newBackingStore the new entity backing store
     */
    protected void setBackingStore(@Nonnull JsonBackingStore newBackingStore) {
        jsonBackingStore = Constraint.isNotNull(newBackingStore, "JsonBackingStore may not be null");
    }

    
    /**
     * The collection of data which provides the backing store for the processed metadata.
     */
    protected class JsonBackingStore {

        /** Index of identifiers to their entity information. */
        private Map<Key, List<Value>> indexedEntities;

        /** Ordered list of entity information. */
        private List<Value> orderedEntitiess;

        /** Constructor. */
        protected JsonBackingStore() {
            indexedEntities = new ConcurrentHashMap<>();
            orderedEntitiess = new ArrayList<>();
        }

        /**
         * Get the entity information index.
         * 
         * @return the entity information index.
         */
        @Nonnull public Map<Key, List<Value>> getIndexedInformation() {
            return indexedEntities;
        }

        /**
         * Get the ordered entity information.
         * 
         * @return the entity information.
         */
        @Nonnull public List<Value> getOrderedInformation() {
            return orderedEntitiess;
        }

    }
}
