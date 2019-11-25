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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultUserInfoSigningAlgLookupFunction;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * Action that creates a {@link UserInfo} object shell, and sets it to work context
 * {@link OIDCAuthenticationResponseContext} located under {@link ProfileRequestContext#getOutboundMessageContext()}.
 * 
 * By default sub claim is added. If the response is to be signed, also iss and aud claims are added.
 */
@SuppressWarnings("rawtypes")
public class AddUserInfoShell extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddUserInfoShell.class);

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** OP ID to populate into Issuer element. */
    @Nonnull
    private String issuerId;

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** The RelyingPartyContext to operate on. */
    @Nullable
    private RelyingPartyContext rpCtx;

    /** Strategy used to determine user info response signing algorithm. */
    @Nonnull
    private Function<ProfileRequestContext, JWSAlgorithm> userInfoSigAlgStrategy;

    /** Constructor. */
    public AddUserInfoShell() {
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
        userInfoSigAlgStrategy = new DefaultUserInfoSigningAlgLookupFunction();
    }

    /**
     * Set the strategy used to user info signing algorithm lookup strategy.
     * 
     * @param strategy lookup strategy
     */
    public void
            setUserInfoSigningAlgLookupStrategy(@Nonnull final Function<ProfileRequestContext, JWSAlgorithm> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        userInfoSigAlgStrategy =
                Constraint.isNotNull(strategy, "User Info Signing Algorithm lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null) {
            log.debug("{} No relying party context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        issuerId = issuerLookupStrategy.apply(profileRequestContext);
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        UserInfo userInfo = new UserInfo(new Subject(getOidcResponseContext().getSubject()));
        if (userInfoSigAlgStrategy.apply(profileRequestContext) != null) {
            userInfo.setClaim("aud",rpCtx.getRelyingPartyId());
            userInfo.setIssuer(new Issuer(issuerId));
        }
        log.debug("{} Setting userinfo response shell to response context {}", getLogPrefix(),
                userInfo.toJSONObject().toJSONString());
        getOidcResponseContext().setUserInfo(userInfo);
    }

}