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
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A base class for {@link ClientInformationResolver}s.
 */
public abstract class AbstractClientInformationResolver extends AbstractIdentifiableInitializableComponent 
    implements ClientInformationResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AbstractClientInformationResolver.class);
    
    /** Backing store for runtime Client Information data. */
    private ClientBackingStore clientBackingStore;
    
    /** {@inheritDoc} */
    @Override protected final void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        try {
            initClientInformationResolver();
        } catch (ComponentInitializationException e) {
            log.error("Client information provider failed to properly initialize", e);
        }
    }
    
    protected void initClientInformationResolver() throws ComponentInitializationException {
        clientBackingStore = createNewBackingStore();
    }
    
    /** {@inheritDoc} */
    @Override
    public Iterable<OIDCClientInformation> resolve(CriteriaSet criteria) throws ResolverException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);

        final ClientIDCriterion clientIdCriterion = criteria.get(ClientIDCriterion.class);
        if (clientIdCriterion == null || clientIdCriterion.getClientID() == null) {
            log.trace("No client ID criteria found, returning all");
            return getBackingStore().getOrderedInformation();
        }
        //TODO: support other criterion
        return lookupClientID(clientIdCriterion.getClientID());
    }

    /** {@inheritDoc} */
    @Override
    public OIDCClientInformation resolveSingle(CriteriaSet criteria) throws ResolverException {
        final Iterable<OIDCClientInformation> iterable = resolve(criteria);
        if (iterable != null) {
            final Iterator<OIDCClientInformation> iterator = iterable.iterator();
            if (iterator != null && iterator.hasNext()) {
                return iterator.next();
            }
        }
        log.warn("Could not find any clients with the given criteria");
        return null;
    }

    /**
     * Get list of information matching a client id.
     * 
     * @param clientId client ID to lookup
     * @return a list of information
     * @throws ResolverException if an error occurs
     */
    @Nonnull @NonnullElements protected List<OIDCClientInformation> lookupClientID(
            @Nonnull @NotEmpty final ClientID clientId)
            throws ResolverException {
        if (!isInitialized()) {
            throw new ResolverException("Metadata resolver has not been initialized");
        }

        if (clientId == null || Strings.isNullOrEmpty(clientId.getValue())) {
            log.debug("Client information clientID was null or empty, skipping search for it");
            return Collections.emptyList();
        }

        List<OIDCClientInformation> allInformation = lookupIndexedEntityID(clientId);
        if (allInformation.isEmpty()) {
            log.debug("Client backing store does not contain any information with the ID: {}", clientId);
            return allInformation;
        }
        return allInformation;
    }

    /**
     * Lookup the specified client ID from the index. The returned list will be a copy of what is stored in the backing
     * index, and is safe to be manipulated by callers.
     * 
     * @param clientId the client ID to lookup
     * 
     * @return list copy of indexed client IDs, may be empty, will never be null
     */
    @Nonnull @NonnullElements protected List<OIDCClientInformation> lookupIndexedEntityID(
            @Nonnull @NotEmpty final ClientID clientId) {
        List<OIDCClientInformation> allInformation = getBackingStore().getIndexedInformation().get(clientId);
        if (allInformation != null) {
            return new ArrayList<>(allInformation);
        } else {
            return Collections.emptyList();
        }
    }

    /**
     * Create a new backing store instance for Client Information data. Subclasses may override to return a more
     * specialized subclass type. Note this method does not make the returned backing store the effective one in use.
     * The caller is responsible for calling {@link #setBackingStore(EntityBackingStore)} to make it the effective
     * instance in use.
     * 
     * @return the new backing store instance
     */
    @Nonnull protected ClientBackingStore createNewBackingStore() {
        return new ClientBackingStore();
    }

    /**
     * Get the EntityDescriptor backing store currently in use by the metadata resolver.
     * 
     * @return the current effective entity backing store
     */
    @Nonnull protected ClientBackingStore getBackingStore() {
        return clientBackingStore;
    }

    /**
     * Set the EntityDescriptor backing store currently in use by the metadata resolver.
     * 
     * @param newBackingStore the new entity backing store
     */
    protected void setBackingStore(@Nonnull ClientBackingStore newBackingStore) {
        clientBackingStore = Constraint.isNotNull(newBackingStore, "ClientBackingStore may not be null");
    }

    /**
     * Pre-process the specified entity descriptor, updating the specified entity backing store instance as necessary.
     * 
     * @param entityDescriptor the target entity descriptor to process
     * @param backingStore the backing store instance to update
     */
    protected void preProcessEntityDescriptor(@Nonnull final OIDCClientInformation entityDescriptor,
            @Nonnull final ClientBackingStore backingStore) {

        backingStore.getOrderedInformation().add(entityDescriptor);
        indexEntityDescriptor(entityDescriptor, backingStore);
    }
    
    /**
     * Remove from the backing store all metadata for the entity with the given entity ID.
     * 
     * @param clientId the entity ID of the metadata to remove
     * @param backingStore the backing store instance to update
     */
    protected void removeByEntityID(@Nonnull final ClientID clientId, @Nonnull final ClientBackingStore backingStore) {
        final Map<ClientID, List<OIDCClientInformation>> indexedDescriptors = backingStore.getIndexedInformation();
        final List<OIDCClientInformation> descriptors = indexedDescriptors.get(clientId);
        if (descriptors != null) {
            backingStore.getOrderedInformation().removeAll(descriptors);
        }
        indexedDescriptors.remove(clientId);
    }

    /**
     * Index the specified entity descriptor, updating the specified entity backing store instance as necessary.
     * 
     * @param entityDescriptor the target entity descriptor to process
     * @param backingStore the backing store instance to update
     */
    protected void indexEntityDescriptor(@Nonnull final OIDCClientInformation entityDescriptor,
            @Nonnull final ClientBackingStore backingStore) {

        ClientID clientId = entityDescriptor.getID();
        if (clientId != null) {
            List<OIDCClientInformation> entities = backingStore.getIndexedInformation().get(clientId);
            if (entities == null) {
                entities = new ArrayList<>();
                backingStore.getIndexedInformation().put(clientId, entities);
            } else if (!entities.isEmpty()) {
                log.warn("Detected duplicate Client Information for client ID: {}", clientId);
            }
            entities.add(entityDescriptor);
        }
    }

    /**
     * The collection of data which provides the backing store for the processed metadata.
     */
    protected class ClientBackingStore {

        /** Index of client IDs to their information. */
        private Map<ClientID, List<OIDCClientInformation>> indexedClients;

        /** Ordered list of client information. */
        private List<OIDCClientInformation> orderedClients;

        /** Constructor. */
        protected ClientBackingStore() {
            indexedClients = new ConcurrentHashMap<>();
            orderedClients = new ArrayList<>();
        }

        /**
         * Get the client information index.
         * 
         * @return the client information index.
         */
        @Nonnull public Map<ClientID, List<OIDCClientInformation>> getIndexedInformation() {
            return indexedClients;
        }

        /**
         * Get the ordered client information.
         * 
         * @return the client information.
         */
        @Nonnull public List<OIDCClientInformation> getOrderedInformation() {
            return orderedClients;
        }

    }
}
