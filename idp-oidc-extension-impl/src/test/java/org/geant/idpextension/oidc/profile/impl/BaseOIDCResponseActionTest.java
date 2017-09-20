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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import net.shibboleth.idp.profile.RequestContextBuilder;

/** {@link InitializeAuthenticationContext} unit test. */
abstract class BaseOIDCResponseActionTest {

    protected RequestContext requestCtx;
    protected OIDCAuthenticationResponseContext respCtx;
    protected AuthenticationRequest request;
    @SuppressWarnings("rawtypes")
	protected ProfileRequestContext profileRequestCtx;
    Credential credential = new BaseOIDCResponseActionTest.mockCredential();
    
    @SuppressWarnings({ "unchecked" })
    @BeforeMethod
    protected void setUp() throws Exception {
        request = AuthenticationRequest
                .parse("response_type=id_token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20profile&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        requestCtx = new RequestContextBuilder().setInboundMessage(request).buildRequestContext();
        final MessageContext<AuthenticationResponse> msgCtx = new MessageContext<AuthenticationResponse>();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        profileRequestCtx.setOutboundMessageContext(msgCtx);
        respCtx = new OIDCAuthenticationResponseContext();
        profileRequestCtx.getOutboundMessageContext().addSubcontext(respCtx);
    }
    
    protected void setIdTokenToResponseContext(String iss, String sub, String aud, Date exp, Date iat){
        List<Audience> audience = new ArrayList<Audience>();
        audience.add(new Audience(aud));
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(new Issuer(iss),
                new Subject(sub), audience, exp, iat);
        respCtx.setIDToken(idToken);
    }
    
    protected void signIdTokenInResponseContext() throws ParseException, JOSEException{
        SignedJWT jwt = null;
        jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("id").build(), respCtx.getIDToken().toJWTClaimsSet());
        jwt.sign(new RSASSASigner(credential.getPrivateKey()));
        respCtx.setSignedIDToken(jwt);
       
    }
    
    public class mockCredential implements Credential{

    	PrivateKey priv;
    	PublicKey pub;
    	
    	mockCredential(){
    		try {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				KeyPair pair = keyGen.generateKeyPair();
				priv = pair.getPrivate();
				pub  = pair.getPublic();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}	
    	}
    	
		@Override
		public CredentialContextSet getCredentialContextSet() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Class<? extends Credential> getCredentialType() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public String getEntityId() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Collection<String> getKeyNames() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public PrivateKey getPrivateKey() {
			return priv;
		}

		@Override
		public PublicKey getPublicKey() {
			return pub;
		}

		@Override
		public SecretKey getSecretKey() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public UsageType getUsageType() {
			// TODO Auto-generated method stub
			return null;
		}
    	
    }
 
}