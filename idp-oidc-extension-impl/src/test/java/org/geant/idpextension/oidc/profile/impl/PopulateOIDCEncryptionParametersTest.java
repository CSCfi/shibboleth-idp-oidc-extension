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