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

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.storage.ReplayCache;
import org.opensaml.storage.impl.MemoryStorageService;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Function;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link ValidateEndpointAuthentication}.
 */
public class ValidateEndpointAuthenticationTest {
    
    ClientID clientId;
    Secret clientSecret;
    
    URI endpointUri;
    
    RSAPrivateKey rsaPrivateKey;
    RSAPublicKey rsaPublicKey;
    
    @BeforeClass
    public void initKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        final KeyPair keyPair = keyGen.genKeyPair();
        rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
    }
    
    @BeforeMethod
    public void init() throws URISyntaxException {
        clientId = new ClientID("mockId");
        clientSecret = new Secret("secret1234567890secret1234567890secret1234567890");
        endpointUri = new URI("https://mock.example.org/");
    }
    
    protected RequestContext initializeRequestCtx(final TokenRequest request, 
            final ClientAuthenticationMethod storedMethod, boolean sameSecret) throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();

        @SuppressWarnings("rawtypes")
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        OIDCMetadataContext oidcContext = new OIDCMetadataContext();
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setTokenEndpointAuthMethod(storedMethod);
        if (storedMethod != null && storedMethod.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            RSAKey rsaKey;
            if (sameSecret) {
                rsaKey = new RSAKey.Builder(rsaPublicKey).build();
            } else {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                rsaKey = new RSAKey.Builder((RSAPublicKey)keyGen.genKeyPair().getPublic()).build();
            }
            JWKSet jwkSet = new JWKSet(rsaKey);
            metadata.setJWKSet(jwkSet);
        }
        Secret secret = sameSecret ? clientSecret : new Secret("WRONG1234567890secret1234567890secret1234567890");
        OIDCClientInformation clientInformation = 
                new OIDCClientInformation(clientId, new Date(), metadata, secret);
        oidcContext.setClientInformation(clientInformation);
        prc.getInboundMessageContext().addSubcontext(oidcContext);
        return requestCtx;
    }
    
    protected TokenRequest initializeTokenRequest(final ClientAuthenticationMethod method) throws JOSEException {
        final ClientAuthentication clientAuth;
        if (method.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            clientAuth = new ClientSecretBasic(clientId, clientSecret);
        } else if (method.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            clientAuth = new ClientSecretPost(clientId, clientSecret);
        } else if (method.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            clientAuth = new ClientSecretJWT(clientId, endpointUri, JWSAlgorithm.HS256, clientSecret);
        } else if (method.equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            clientAuth = new PrivateKeyJWT(clientId, endpointUri, JWSAlgorithm.RS256, rsaPrivateKey, null, null);
        } else {
            clientAuth = null;
        }
        AuthorizationGrant authzGrant = new AuthorizationCodeGrant(new AuthorizationCode(), null);
        return new TokenRequest(null, clientAuth, authzGrant);        
    }
    
    protected ValidateEndpointAuthentication constructAction(final Function<ProfileRequestContext, 
            List<ClientAuthenticationMethod>> newFunction) throws ComponentInitializationException {
        ValidateEndpointAuthentication action = new ValidateEndpointAuthentication();
        ReplayCache replayCache = new ReplayCache();
        MemoryStorageService storageService = new MemoryStorageService();
        storageService.setId("mockId");
        storageService.initialize();
        replayCache.setStorage(storageService);
        action.setReplayCache(replayCache);
        if (newFunction != null) {
            action.setTokenEndpointAuthMethodsLookupStrategy(newFunction);
        }
        action.initialize();
        return action;
    }
    
    @Test
    public void testNoEnabledMethods() throws Exception {
        ValidateEndpointAuthentication action = constructAction(null);
        final Event event = 
                action.execute(initializeRequestCtx(
                        initializeTokenRequest(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), null, true));
        ActionTestingSupport.assertEvent(event, EventIds.ACCESS_DENIED);
    }
    
    protected void testClientAuth(final ClientAuthenticationMethod clientAuth, boolean success) throws Exception {
        ValidateEndpointAuthentication action = 
                constructAction(new ListMethodsFunction(clientAuth));
        final Event event = 
                action.execute(initializeRequestCtx(
                        initializeTokenRequest(clientAuth), clientAuth, success));
        if (success) {
            Assert.assertNull(event);
        } else {
            ActionTestingSupport.assertEvent(event, EventIds.ACCESS_DENIED);
        }
    }

    protected void testSuccessClientAuth(final ClientAuthenticationMethod clientAuth) throws Exception {
        testClientAuth(clientAuth, true);
    }

    protected void testFailingClientAuth(final ClientAuthenticationMethod clientAuth) throws Exception {
        testClientAuth(clientAuth, false);
    }
    
    @Test
    public void testBasic() throws Exception {
        testSuccessClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testPost() throws Exception {
        testSuccessClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_POST);
    }

    @Test
    public void testSecretJwt() throws Exception {
        testSuccessClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
    }

    @Test
    public void testPrivateKeyJwt() throws Exception {
        testSuccessClientAuth(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    }

    @Test
    public void testFailingBasic() throws Exception {
        testFailingClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    public void testFailingPost() throws Exception {
        testFailingClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_POST);
    }

    @Test
    public void testFailingSecretJwt() throws Exception {
        testFailingClientAuth(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
    }

    @Test
    public void testFailingPrivateKeyJwt() throws Exception {
        testFailingClientAuth(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    }

    class ListMethodsFunction extends AbstractRelyingPartyLookupFunction<List<ClientAuthenticationMethod>> {

        private List<ClientAuthenticationMethod> list;
        
        public ListMethodsFunction(ClientAuthenticationMethod... methods) {
            list = Arrays.asList(methods);
        }
        
        @Override
        public List<ClientAuthenticationMethod> apply(ProfileRequestContext input) {
            return list;
        }   
    }
}