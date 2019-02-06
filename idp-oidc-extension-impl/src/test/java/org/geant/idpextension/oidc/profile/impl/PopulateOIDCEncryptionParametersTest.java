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

package org.geant.idpextension.oidc.profile.impl;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import java.security.NoSuchAlgorithmException;

import org.opensaml.profile.action.EventIds;
import org.opensaml.saml.saml2.profile.context.EncryptionContext;
import org.opensaml.xmlsec.EncryptionParameters;
import org.opensaml.xmlsec.EncryptionParametersResolver;
import org.opensaml.xmlsec.criterion.EncryptionOptionalCriterion;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/** {@link PopulateOIDCEncryptionParameters} unit test. */
public class PopulateOIDCEncryptionParametersTest extends BaseOIDCResponseActionTest {

    private PopulateOIDCEncryptionParameters action;

    private MockEncryptionParametersResolver resolver;

    @BeforeMethod
    private void init() throws ComponentInitializationException {
        action = new PopulateOIDCEncryptionParameters();
        resolver = new MockEncryptionParametersResolver();
        action.setEncryptionParametersResolver(resolver);
        action.initialize();
    }

    /**
     * Test basic success case for encryption.
     */
    @Test
    public void testSuccessEncryption() throws NoSuchAlgorithmException, ComponentInitializationException {
        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNotNull(profileRequestCtx.getSubcontext(RelyingPartyContext.class)
                .getSubcontext(EncryptionContext.class).getAssertionEncryptionParameters());
    }

    /**
     * Test basic success case for decryption.
     */
    @Test
    public void testSuccessDecryption() throws NoSuchAlgorithmException, ComponentInitializationException {
        action = new PopulateOIDCEncryptionParameters();
        action.setForDecryption(true);
        action.setEncryptionParametersResolver(new MockEncryptionParametersResolver());
        action.initialize();

        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNotNull(profileRequestCtx.getSubcontext(RelyingPartyContext.class)
                .getSubcontext(EncryptionContext.class).getAttributeEncryptionParameters());
    }

    /**
     * Test success case for failing to resolve when failing is an option.
     */
    @Test
    public void testSuccessFailsToResolve() throws NoSuchAlgorithmException, ComponentInitializationException {
        resolver.resolve = false;
        resolver.optional = true;

        ActionTestingSupport.assertProceedEvent(action.execute(requestCtx));
        Assert.assertNull(profileRequestCtx.getSubcontext(RelyingPartyContext.class)
                .getSubcontext(EncryptionContext.class).getAssertionEncryptionParameters());
    }

    /**
     * Test failing to resolve when failing is not an option.
     */
    @Test
    public void testFailureFailsToResolve() throws NoSuchAlgorithmException, ComponentInitializationException {
        resolver.resolve = false;
        ActionTestingSupport.assertEvent(action.execute(requestCtx), EventIds.INVALID_SEC_CFG);
    }

    /**
     * Test setting null strategy for configurations.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailureNullStrategyConf() {
        action = new PopulateOIDCEncryptionParameters();
        action.setConfigurationLookupStrategy(null);
    }

    /**
     * Test setting null strategy for encryption context.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailureNullStrategyEncrContext() {
        action = new PopulateOIDCEncryptionParameters();
        action.setEncryptionContextLookupStrategy(null);
    }

    /**
     * Test setting null strategy for metadata context.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailureNullStrategyMetadataContext() {
        action = new PopulateOIDCEncryptionParameters();
        action.setOIDCMetadataContextContextLookupStrategy(null);
    }

    /**
     * Test setting null strategy for encryption params resolver.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailureNullStrategyEncrParamas() {
        action = new PopulateOIDCEncryptionParameters();
        action.setEncryptionParametersResolver(null);
    }

    public class MockEncryptionParametersResolver implements EncryptionParametersResolver {

        public boolean resolve = true;

        public boolean optional;

        @Override
        public Iterable<EncryptionParameters> resolve(CriteriaSet criteria) throws ResolverException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public EncryptionParameters resolveSingle(CriteriaSet criteria) throws ResolverException {
            if (optional) {
                criteria.add(new EncryptionOptionalCriterion(true));
            }
            return resolve ? new EncryptionParameters() : null;
        }

    }

}