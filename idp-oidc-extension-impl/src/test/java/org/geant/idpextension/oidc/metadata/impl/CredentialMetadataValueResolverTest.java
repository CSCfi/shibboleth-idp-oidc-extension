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

import java.io.File;
import java.util.Arrays;

import org.geant.idpextension.oidc.config.OIDCProviderInformationConfiguration;
import org.geant.idpextension.oidc.profile.spring.factory.BasicJWKCredentialFactoryBean;
import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.config.SecurityConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link CredentialMetadataValueResolver}.
 */
public class CredentialMetadataValueResolverTest {
    
    protected RequestContext requestCtx;
    protected ProfileRequestContext profileRequestCtx;

    @BeforeMethod
    protected void setUpContext() throws ComponentInitializationException {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
    }
    
    protected CredentialMetadataValueResolver initResolver(final String fileName) throws Exception {
        final BasicJWKCredentialFactoryBean factory = new BasicJWKCredentialFactoryBean();
        factory.setJWKResource(new FileSystemResource(new File(fileName)));
        factory.afterPropertiesSet();
        Credential credential = factory.getObject();
        final CredentialMetadataValueResolver resolver = new CredentialMetadataValueResolver();
        resolver.setId("mockId");
        resolver.initialize();
        RelyingPartyContext rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class, true);
        OIDCProviderInformationConfiguration profileConfig = new OIDCProviderInformationConfiguration();
        SecurityConfiguration secConfig = new SecurityConfiguration();
        SignatureSigningConfiguration signConfig = Mockito.mock(SignatureSigningConfiguration.class);
        Mockito.when(signConfig.getSigningCredentials()).thenReturn(Arrays.asList(credential));
        secConfig.setSignatureSigningConfiguration(signConfig);
        profileConfig.setSecurityConfiguration(secConfig);
        rpCtx.setProfileConfig(profileConfig);
        return resolver;
    }
    
    @Test
    public void testRsa() throws Exception {
        final CredentialMetadataValueResolver resolver = initResolver("src/test/resources/org/geant/idpextension/oidc/metadata/impl/idp-signing-rs256.jwk");
        final Object result = resolver.resolveSingle(profileRequestCtx);
        Assert.assertNotNull(result);
        System.out.println(result);
        Assert.assertTrue(result instanceof JSONArray);
        final JSONObject json = (JSONObject)((JSONArray) result).get(0);
        Assert.assertEquals(json.keySet().size(), 6);
        Assert.assertEquals(json.get("kty"), "RSA");
        Assert.assertEquals(json.get("n"), "pNf03ghVzMAw5sWrwDAMAZdSYNY2q7OVlxMInljMgz8XB5mf8XKH3EtP7AKrb8IAf7rGhfuH3T1N1C7F-jwIeYjXxMm2nIAZ0hXApgbccvBpf4n2H7IZflMjt4A3tt587QQSxQ069drCP4sYevxhTcLplJy6RWA0cLj-5CHyWy94zPeeA4GRd6xgHFLz0RNiSF0pF0kE4rmRgQVZ-b4_BmD9SsWnIpwhms5Ihciw36WyAGQUeZqULGsfwAMwlNLIaTCBLAoRgv370p-XsLrgz86pTkNBJqXP5GwI-ZfgiLmJuHjQ9l85KqHM87f-QdsqiV8KoRcslgXPqb6VOTJBVw");
        Assert.assertEquals(json.get("e"), "AQAB");
        Assert.assertEquals(json.get("alg"), "RS256");
        Assert.assertEquals(json.get("use"), "sig");
        Assert.assertEquals(json.get("kid"), "testkey");
    }

}
