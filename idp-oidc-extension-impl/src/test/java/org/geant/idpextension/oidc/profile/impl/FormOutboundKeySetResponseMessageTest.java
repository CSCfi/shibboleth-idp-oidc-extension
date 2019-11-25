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

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.config.OIDCPublishKeySetConfiguration;
import org.geant.idpextension.oidc.messaging.JSONSuccessResponse;
import org.geant.idpextension.oidc.profile.api.OIDCSecurityConfiguration;
import org.geant.idpextension.oidc.profile.spring.factory.BasicJWKCredentialFactoryBean;
import org.mockito.Mockito;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SignatureSigningConfiguration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;

/** {@link FormOutboundKeySetResponseMessage} unit test. */
public class FormOutboundKeySetResponseMessageTest {

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext profileRequestCtx;

    private FormOutboundKeySetResponseMessage action;

    private RequestContext requestCtx;

    private OIDCPublishKeySetConfiguration profileConf;

    private RelyingPartyContext rpCtx;

    @SuppressWarnings({"unchecked"})
    @BeforeMethod
    public void init() throws Exception {
        requestCtx = new RequestContextBuilder().buildRequestContext();
        final MessageContext<Response> msgCtx = new MessageContext<Response>();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setOutboundMessageContext(msgCtx);
        rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class, true);

        List<Credential> signCreds = new ArrayList<Credential>();
        BasicJWKCredentialFactoryBean factory = new BasicJWKCredentialFactoryBean();
        factory.setJWKResource(new ClassPathResource("credentials/idp-signing-es.jwk"));
        factory.afterPropertiesSet();
        signCreds.add(factory.getObject());

        factory = new BasicJWKCredentialFactoryBean();
        factory.setJWKResource(new ClassPathResource("credentials/idp-signing-rs.jwk"));
        factory.afterPropertiesSet();
        signCreds.add(factory.getObject());

        factory = new BasicJWKCredentialFactoryBean();
        factory.setJWKResource(new ClassPathResource("credentials/idp-encryption-rsa.jwk"));
        factory.afterPropertiesSet();
        List<Credential> encCreds = new ArrayList<Credential>();
        encCreds.add(factory.getObject());

        SignatureSigningConfiguration signConfig = Mockito.mock(SignatureSigningConfiguration.class);
        Mockito.when(signConfig.getSigningCredentials()).thenReturn(signCreds);
        EncryptionConfiguration decConfig = Mockito.mock(EncryptionConfiguration.class);
        Mockito.when(decConfig.getKeyTransportEncryptionCredentials()).thenReturn(encCreds);

        OIDCSecurityConfiguration secConf = new OIDCSecurityConfiguration();
        secConf.setSignatureSigningConfiguration(signConfig);
        secConf.setRequestObjectDecryptionConfiguration(decConfig);

        profileConf = new OIDCPublishKeySetConfiguration();
        profileConf.setSecurityConfiguration(secConf);
        rpCtx.setProfileConfig(profileConf);
        action = new FormOutboundKeySetResponseMessage();
        action.initialize();
    }

    /**
     * Test that action is able to form success message.
     * 
     * @throws java.text.ParseException
     */
    @Test
    public void testSuccessMessage() throws ComponentInitializationException, URISyntaxException, ParseException,
            JOSEException, java.text.ParseException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(profileRequestCtx.getOutboundMessageContext().getMessage() instanceof JSONSuccessResponse);
        JSONSuccessResponse resp = (JSONSuccessResponse) profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertTrue(resp.indicatesSuccess());
        JSONObject keyset = resp.toHTTPResponse().getContentAsJSONObject();
        JSONArray keys = (JSONArray) keyset.get("keys");
        //The test for content could be more thorough
        Assert.assertEquals(keys.size(), 3);
    }

    /**
     * Test case of no sec conf.
     */
    @Test
    public void testFailNoSecConf()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        profileConf.setSecurityConfiguration(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    /**
     * Test case of no profile conf.
     */
    @Test
    public void testFailNoProfileConf()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        rpCtx.setProfileConfig(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    /**
     * Test case of no rp ctx.
     */
    @Test
    public void testFailNoRPCtx()
            throws ComponentInitializationException, URISyntaxException, ParseException, JOSEException {
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

}