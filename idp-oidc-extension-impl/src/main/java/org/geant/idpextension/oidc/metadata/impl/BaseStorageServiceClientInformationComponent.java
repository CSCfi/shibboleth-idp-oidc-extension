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

package org.geant.idpextension.oidc.metadata.impl;

import javax.annotation.Nonnull;

import org.opensaml.storage.StorageService;

import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A base class for {@link ClientInformationManager} and {@link ClientInformationResolver} implementations
 * exploiting {@link StorageService} for storing the OIDC client information.
 */
public abstract class BaseStorageServiceClientInformationComponent extends AbstractIdentifiableInitializableComponent {
    
    /** The context name in the {@link StorageService}. */
    public static final String CONTEXT_NAME = "oidcClientInformation";

    /** The {@link StorageService} back-end to use. */
    private StorageService storageService;
    
    /** Constructor. */
    protected BaseStorageServiceClientInformationComponent() {
        super();
    }
    
    /**
     * This method checks to ensure that the {@link StorageService} back-end is not null.
     * 
     * {@inheritDoc}
     */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (getStorageService() == null) {
            throw new ComponentInitializationException("StorageService cannot be null");
        }
    }

    /**
     * Get the {@link StorageService} back-end to use.
     * 
     * @return the back-end to use
     */
    @Nonnull public StorageService getStorageService() {
        return storageService;
    }

    /**
     * Set the {@link StorageService} back-end to use.
     * 
     * @param storage the back-end to use
     */
    public void setStorageService(@Nonnull final StorageService storage) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        storageService = Constraint.isNotNull(storage, "StorageService cannot be null");
    }

}
