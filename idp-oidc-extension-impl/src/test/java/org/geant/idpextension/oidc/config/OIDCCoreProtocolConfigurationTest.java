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

package org.geant.idpextension.oidc.config;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.idp.saml.authn.principal.AuthenticationMethodPrincipal;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link OIDCCoreProtocolConfiguration}
 */
public class OIDCCoreProtocolConfigurationTest {

    private OIDCCoreProtocolConfiguration config;

    @BeforeMethod
    protected void setUp() throws Exception {
        config = new OIDCCoreProtocolConfiguration();
        config.setSecurityConfiguration(new SecurityConfiguration());
        config.initialize();
    }

    @Test
    public void testInitialState() throws ComponentInitializationException {
        Assert.assertEquals(config.getId(), "http://csc.fi/ns/profiles/oidc/sso/browser");
        Assert.assertTrue(config.getAuthenticationFlows().isEmpty());
        Assert.assertTrue(config.getPostAuthenticationFlows().isEmpty());
        Assert.assertTrue(config.getDefaultAuthenticationMethods().isEmpty());
        Assert.assertTrue(config.getAdditionalAudiencesForIdToken().isEmpty());
        Assert.assertEquals(config.getAuthorizeCodeLifetime(), 300000);
        Assert.assertEquals(config.getIDTokenLifetime(), 3600000);
        Assert.assertEquals(config.getAccessTokenLifetime(), 600000);
        Assert.assertEquals(config.getRefreshTokenLifetime(), 7200000);
        Assert.assertFalse(config.getAcrRequestAlwaysEssential());
        Assert.assertTrue(config.getAdditionalAudiencesForIdToken().isEmpty());
        Assert.assertTrue(config.isResolveAttributes());
    }

    @Test
    void testsetResolveAttributes() {
        Assert.assertTrue(config.isResolveAttributes());
        config.setResolveAttributes(false);
        Assert.assertFalse(config.isResolveAttributes());
    }

    @Test
    void testsetDefaultAuthenticationMethods() {
        Assert.assertTrue(config.getDefaultAuthenticationMethods().isEmpty());
        List<Principal> principals = new ArrayList<Principal>();
        principals.add(new AuthenticationMethodPrincipal("value"));
        config.setDefaultAuthenticationMethods(principals);
        Assert.assertTrue(
                config.getDefaultAuthenticationMethods().contains(new AuthenticationMethodPrincipal("value")));
    }

    @Test
    void testsetRefreshTokenLifetime() {
        config.setRefreshTokenLifetimeLookupStrategy(null);
        config.setRefreshTokenLifetime(100);
        Assert.assertEquals(config.getRefreshTokenLifetime(), 100);
    }

    @Test
    void testsetAccessTokenLifetime() {
        config.setAccessTokenLifetime(100);
        Assert.assertEquals(config.getAccessTokenLifetime(), 100);
    }

    @Test
    void testsetAuthorizeCodeLifetime() {
        config.setAuthorizeCodeLifetime(100);
        Assert.assertEquals(config.getAuthorizeCodeLifetime(), 100);
    }

    @Test
    void testsetIDTokenLifetime() {
        config.setIDTokenLifetime(100);
        Assert.assertEquals(config.getIDTokenLifetime(), 100);
    }

    @Test
    void testsetAcrRequestAlwaysEssential() {
        Assert.assertFalse(config.getAcrRequestAlwaysEssential());
        config.setAcrRequestAlwaysEssential(true);
        Assert.assertTrue(config.getAcrRequestAlwaysEssential());
    }

    @Test
    void testsetAdditionalAudiencesForIdToken() {
        Assert.assertTrue(config.getAdditionalAudiencesForIdToken().isEmpty());
        Collection<String> audiences = new ArrayList<String>();
        audiences.add("value");
        config.setAdditionalAudiencesForIdToken(audiences);
        Assert.assertTrue(config.getAdditionalAudiencesForIdToken().contains("value"));
    }

    @Test
    void testsetAuthenticationFlows() {
        Assert.assertTrue(config.getAuthenticationFlows().isEmpty());
        Collection<String> flows = new ArrayList<String>();
        flows.add("value");
        config.setAuthenticationFlows(flows);
        Assert.assertTrue(config.getAuthenticationFlows().contains("value"));
    }

    @Test
    void testsetPostAuthenticationFlows() {
        Assert.assertTrue(config.getPostAuthenticationFlows().isEmpty());
        Collection<String> flows = new ArrayList<String>();
        flows.add("value");
        config.setPostAuthenticationFlows(flows);
        Assert.assertTrue(config.getPostAuthenticationFlows().contains("value"));
    }

}