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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;

import org.geant.idpextension.oidc.messaging.OIDCWebFingerRequest;
import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse;
import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse.Link;
import org.geant.idpextension.oidc.messaging.impl.OIDCWebFingerResponseImpl;
import org.geant.idpextension.oidc.messaging.impl.OIDCWebFingerResponseLinkImpl;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This action builds a response for the OIDC Web Finger. The resource value from the request is directly used as
 * a subject. The issuer link value must be configured.
 */
public class BuildWebFingerResponse extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BuildWebFingerResponse.class);
    
    /** The OIDC WebFinger request. */
    protected OIDCWebFingerRequest request;
    
    /** The OIDC issuer name to be used in the responses. */
    private String oidcIssuer;

    /** Constructor. */
    public BuildWebFingerResponse() {
    }
    
    /**
     * Set the OIDC issuer name to be used in the responses.
     * @param issuer The OIDC issuer name to be used in the responses.
     */
    public void setIssuer(final String issuer) {
        oidcIssuer = Constraint.isNotEmpty(issuer, "The issuer cannot be null!");
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.debug("{} No inbound message context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof OIDCWebFingerRequest)) {
            log.debug("{} No inbound message associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        request = (OIDCWebFingerRequest) message;
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletResponse servletResponse = getHttpServletResponse();
        final Link link = new OIDCWebFingerResponseLinkImpl(request.getRel(), oidcIssuer);
        final List<Link> links = new ArrayList<>();
        links.add(link);
        final OIDCWebFingerResponse response = new OIDCWebFingerResponseImpl(request.getResource(), links);
        servletResponse.setContentType("application/jrd+json");
        servletResponse.setCharacterEncoding("UTF-8");
        final Gson gson = new Gson();
        try {
            gson.toJson(gson.toJsonTree(response), gson.newJsonWriter(servletResponse.getWriter()));
        } catch (IOException e) {
            log.error("{} Could not encode the JSON response to the servlet response", getLogPrefix(), e);
            return;
        }
        
        log.debug("{} WebFinger response successfully applied to the HTTP response", getLogPrefix());
    }
}
