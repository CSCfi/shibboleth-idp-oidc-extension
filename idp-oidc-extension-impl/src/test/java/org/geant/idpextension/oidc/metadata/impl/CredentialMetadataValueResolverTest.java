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
