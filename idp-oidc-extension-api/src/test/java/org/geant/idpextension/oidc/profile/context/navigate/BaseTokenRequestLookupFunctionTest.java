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