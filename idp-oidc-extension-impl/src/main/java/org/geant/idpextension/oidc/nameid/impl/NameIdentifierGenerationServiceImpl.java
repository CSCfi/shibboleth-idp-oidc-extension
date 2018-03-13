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

package org.geant.idpextension.oidc.nameid.impl;

import javax.annotation.Nonnull;

import org.opensaml.saml.saml1.profile.SAML1NameIdentifierGenerator;
import org.opensaml.saml.saml2.profile.SAML2NameIDGenerator;

import net.shibboleth.ext.spring.service.AbstractServiceableComponent;
import net.shibboleth.idp.saml.nameid.NameIdentifierGenerationService;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.IdentifiableComponent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Implementation of {@link NameIdentifierGenerationService}.
 * 
 * OIDC Subject generation takes advantage of saml2 persistent id generators. This class enables a more convenient
 * naming for user to configure the list.
 * 
 * Based on {@link net.shibboleth.idp.saml.nameid.impl.NameIdentifierGenerationServiceImpl} .
 */
public class NameIdentifierGenerationServiceImpl extends AbstractServiceableComponent<NameIdentifierGenerationService>
        implements NameIdentifierGenerationService, IdentifiableComponent {

    /** SAML 2 generator. */
    @NonnullAfterInit
    private SAML2NameIDGenerator saml2Generator;

    /** {@inheritDoc} */
    @Override
    public void setId(@Nonnull @NotEmpty final String id) {
        super.setId(id);
    }

    /**
     * Set the {@link SAML2NameIDGenerator} to use.
     * 
     * @param generator generator to use
     */
    public void setSubjectGenerator(@Nonnull final SAML2NameIDGenerator generator) {
        saml2Generator = Constraint.isNotNull(generator, "SAML2NameIDGenerator cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (saml2Generator == null) {
            throw new ComponentInitializationException("Generator cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    public SAML2NameIDGenerator getSAML2NameIDGenerator() {
        return saml2Generator;
    }

    /** {@inheritDoc} */
    @Override
    public NameIdentifierGenerationService getComponent() {
        return this;
    }

    /** {@inheritDoc} */
    @Override
    public SAML1NameIdentifierGenerator getSAML1NameIdentifierGenerator() {
        // Not supported
        return null;
    }

}