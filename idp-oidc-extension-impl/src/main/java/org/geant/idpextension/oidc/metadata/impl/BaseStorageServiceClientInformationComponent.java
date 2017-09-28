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
