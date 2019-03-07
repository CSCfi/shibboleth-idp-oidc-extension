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

package org.geant.idpextension.oidc.profile.context.navigate;

import net.minidev.json.JSONArray;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenDeliveryClaimsClaimsSet;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/** Base class for testing classes extending {@link AbstractTokenRequestLookupFunction}. */
public class BaseTokenRequestLookupFunctionTest {

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext prc;

    protected MessageContext<AuthenticationRequest> msgCtx;

    protected OIDCAuthenticationResponseContext oidcCtx;

    protected ClientID cliendID = new ClientID();

    protected String issuer = "issuer";

    protected String userPrin = "userPrin";

    protected String subject = "subject";

    protected ACR acr = new ACR("0");

    protected Date iat = new Date();

    protected Date exp = new Date(System.currentTimeMillis() + 1000);

    protected Nonce nonce = new Nonce();

    protected Date authTime = new Date();

    protected URI redirectUri;

    protected Scope scope = new Scope();

    protected String idpSessionId = "idpSessionId";

    protected ClaimsRequest claimsRequest;

    protected ClaimsSet tokenDeliveryClaims = new TokenDeliveryClaimsClaimsSet();

    protected ClaimsSet tokenToIdTokenDeliveryClaims = new TokenDeliveryClaimsClaimsSet();

    protected ClaimsSet tokenToUserInfoTokenDeliveryClaims = new TokenDeliveryClaimsClaimsSet();

    protected JSONArray consentableClaims = new JSONArray();

    protected JSONArray consentedClaims = new JSONArray();

    BaseTokenRequestLookupFunctionTest() {
        try {
            redirectUri = new URI("http://example.com");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        claimsRequest = new ClaimsRequest();
        claimsRequest.addIDTokenClaim("email");
        tokenDeliveryClaims.setClaim("tokenDelivery", "value");
        tokenToIdTokenDeliveryClaims.setClaim("tokenToIdtokenDelivery", "value");
        tokenToUserInfoTokenDeliveryClaims.setClaim("tokenToUserInfotokenDeliveryClaim", "value");
        consentableClaims.add("consentableClaim");
        consentedClaims.add("consentedClaim");
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @BeforeMethod
    protected void setUpCtxs() throws Exception {
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setOutboundMessageContext(new MessageContext());
        oidcCtx = new OIDCAuthenticationResponseContext();
        prc.getOutboundMessageContext().addSubcontext(oidcCtx);
        oidcCtx.setTokenClaimsSet(new AuthorizeCodeClaimsSet.Builder(new SecureRandomIdentifierGenerationStrategy(),
                cliendID, issuer, userPrin, subject, iat, exp, authTime, redirectUri, scope).setACR(acr).setNonce(nonce)
                        .setClaims(claimsRequest).setDlClaims(tokenDeliveryClaims)
                        .setDlClaimsID(tokenToIdTokenDeliveryClaims).setDlClaimsUI(tokenToUserInfoTokenDeliveryClaims)
                        .setConsentableClaims(consentableClaims).setConsentedClaims(consentedClaims).build());
    }

}