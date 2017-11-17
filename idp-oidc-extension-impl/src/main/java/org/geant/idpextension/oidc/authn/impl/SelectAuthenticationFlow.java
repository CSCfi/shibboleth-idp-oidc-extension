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

package org.geant.idpextension.oidc.authn.impl;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.AuthenticationResult;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import net.shibboleth.idp.authn.principal.PrincipalEvalPredicate;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

import org.geant.idpextension.oidc.messaging.context.OIDCRequestedPrincipalContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Based on Based on
 * {@link net.shibboleth.idp.authn.impl.AbstractAuthenticationAction}.
 * Modifications to original is related to handling non essential requested
 * principal.
 * 
 * An authentication action that selects an authentication flow to invoke, or
 * re-uses an existing result for SSO.
 * 
 * <p>
 * This is the heart of the authentication processing sequence, and runs after
 * the {@link AuthenticationContext} has been fully populated. It uses the
 * potential flows, the {@link RequestedPrincipalContext} (if any), and the
 * active results, to decide how to proceed.
 * </p>
 * 
 * <p>
 * Normal processing behavior can be circumvented if
 * {@link AuthenticationContext#getSignaledFlowId()} is set, which causes an
 * active result from that flow to be reused, or that flow to be invoked, if at
 * all possible, subject to the usual predicates and requested principal
 * constraints noted below.
 * </p>
 * 
 * <p>
 * Otherwise, if there is no {@link RequestedPrincipalContext}, then an active
 * result will be reused, unless the request requires forced authentication. If
 * not possible, then a potential flow will be selected and its ID returned as
 * the result of the action.
 * </p>
 * 
 * <p>
 * If there are requested essential principals, then the results or flows chosen
 * must "match" the request information according to the
 * {@link net.shibboleth.idp.authn.principal.PrincipalEvalPredicateFactoryRegistry}
 * attached to the context. If the requested principals are not essential and
 * there is no "match" for flows, flow is selected as if none was requested in
 * the first place. The "favorSSO" option determines whether to select a flow
 * specifically in the order specified by the {@link RequestedPrincipalContext},
 * or to favor an active but matching result over a new flow. Forced
 * authentication trumps the use of any active result.
 * </p>
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID} (reuse
 *        of a result, i.e., SSO)
 * @event {@link AuthnEventIds#NO_PASSIVE}
 * @event {@link AuthnEventIds#NO_POTENTIAL_FLOW}
 * @event {@link AuthnEventIds#REQUEST_UNSUPPORTED}
 * @event Selected flow ID to execute
 * @pre <pre>
 * ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null
 * </pre>
 * @pre The content of {@link AuthenticationContext#getPotentialFlows()} are
 *      assumed to be acceptable with respect to passive and forced
 *      authentication requirements, etc.
 * @post If a result is reused,
 *       {@link AuthenticationContext#getAuthenticationResult()} will return
 *       that result. Otherwise,
 *       {@link AuthenticationContext#getAttemptedFlow()} will return the flow
 *       selected for execution and returned as an event.
 */

@SuppressWarnings("rawtypes")
public class SelectAuthenticationFlow extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SelectAuthenticationFlow.class);

    /** Whether SSO trumps explicit relying party flow preference. */
    private boolean favorSSO;

    /** A subordinate RequestedPrincipalContext, if any. */
    @Nullable
    private RequestedPrincipalContext requestedPrincipalCtx;

    /**
     * Get whether SSO should trump explicit relying party flow preference.
     * 
     * @return whether SSO should trump explicit relying party flow preference
     */
    public boolean getFavorSSO() {
        return favorSSO;
    }

    /**
     * Set whether SSO should trump explicit relying party flow preference.
     * 
     * @param flag
     *            whether SSO should trump explicit relying party flow
     *            preference
     */
    public void setFavorSSO(final boolean flag) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        favorSSO = flag;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        requestedPrincipalCtx = authenticationContext.getSubcontext(RequestedPrincipalContext.class);
        if (requestedPrincipalCtx != null) {
            if (requestedPrincipalCtx.getOperator() == null || requestedPrincipalCtx.getRequestedPrincipals().isEmpty()) {
                requestedPrincipalCtx = null;
            }
        }

        // Detect a previous attempted flow, and move it to the intermediate
        // collection.
        // This will prevent re-selecting the same (probably failed) flow again
        // as part of
        // general flow selection. A flow might signal to explicitly re-run
        // another flow anyway.
        if (authenticationContext.getAttemptedFlow() != null) {
            log.info("{} Moving incomplete flow {} to intermediate set", getLogPrefix(), authenticationContext
                    .getAttemptedFlow().getId());
            authenticationContext.getIntermediateFlows().put(authenticationContext.getAttemptedFlow().getId(),
                    authenticationContext.getAttemptedFlow());
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (authenticationContext.getSignaledFlowId() != null) {
            doSelectSignaledFlow(profileRequestContext, authenticationContext);
        } else if (requestedPrincipalCtx == null) {
            doSelectNoRequestedPrincipals(profileRequestContext, authenticationContext);
        } else {
            if (!doSelectRequestedPrincipals(profileRequestContext, authenticationContext)) {
                final OIDCRequestedPrincipalContext oidcRPCtx = authenticationContext.getSubcontext(
                        OIDCRequestedPrincipalContext.class, false);
                if (oidcRPCtx != null && !oidcRPCtx.isEssential()) {
                    log.debug("{} mismatch for voluntary acr, retry with any", getLogPrefix());
                    // We hide requested principal ctx from rest of the actions,
                    // namely finalizeauthentication
                    oidcRPCtx.addSubcontext(requestedPrincipalCtx);
                    authenticationContext.removeSubcontext(requestedPrincipalCtx);
                    doSelectNoRequestedPrincipals(profileRequestContext, authenticationContext);
                    return;

                }
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.REQUEST_UNSUPPORTED);
            }
        }
    }

    // Checkstyle: MethodLength|CyclomaticComplexity|ReturnCount OFF
    /**
     * Executes the selection process in the presence of an explicit flow
     * signal.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     */
    private void doSelectSignaledFlow(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        // See if flow exists.
        final AuthenticationFlowDescriptor flow = authenticationContext.getPotentialFlows().get(
                authenticationContext.getSignaledFlowId());
        if (flow == null) {
            log.error("{} Signaled flow {} is not available", getLogPrefix(), authenticationContext.getSignaledFlowId());
            ActionSupport.buildEvent(profileRequestContext,
                    authenticationContext.isPassive() ? AuthnEventIds.NO_PASSIVE : AuthnEventIds.NO_POTENTIAL_FLOW);
            authenticationContext.setSignaledFlowId(null);
            return;
        }

        // Clear state.
        authenticationContext.setSignaledFlowId(null);

        log.debug("{} Attempting to honor signaled flow {}", getLogPrefix(), flow.getId());

        // If not forced, or we just did it, check for an active result for that
        // flow.

        final AuthenticationResult activeResult;
        if (!authenticationContext.isForceAuthn()) {
            activeResult = authenticationContext.getActiveResults().get(flow.getId());
        } else if (authenticationContext.getInitialAuthenticationResult() != null
                && authenticationContext.getInitialAuthenticationResult().getAuthenticationFlowId()
                        .equals(flow.getId())) {
            activeResult = authenticationContext.getInitialAuthenticationResult();
        } else {
            activeResult = null;
        }

        if (activeResult != null) {
            if (requestedPrincipalCtx != null) {
                for (final Principal p : requestedPrincipalCtx.getRequestedPrincipals()) {
                    final PrincipalEvalPredicate predicate = requestedPrincipalCtx.getPredicate(p);
                    if (predicate != null) {
                        if (predicate.apply(activeResult)) {
                            selectActiveResult(profileRequestContext, authenticationContext, activeResult);
                            return;
                        }
                    } else {
                        log.warn("{} Configuration does not support requested principal evaluation with "
                                + "operator '{}' and type '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                                p.getClass());
                    }
                }
            } else {
                selectActiveResult(profileRequestContext, authenticationContext, activeResult);
                return;
            }
        }

        // Try and use the inactive flow.

        // Check for IsPassive compatibility.
        if (authenticationContext.isPassive() && !flow.isPassiveAuthenticationSupported()) {
            log.error("{} Signaled flow {} does not support passive authentication", getLogPrefix(), flow.getId());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_PASSIVE);
            return;
        } else if (requestedPrincipalCtx != null) {
            for (final Principal p : requestedPrincipalCtx.getRequestedPrincipals()) {
                final PrincipalEvalPredicate predicate = requestedPrincipalCtx.getPredicate(p);
                if (predicate != null) {
                    if (predicate.apply(flow) && flow.apply(profileRequestContext)) {
                        selectInactiveFlow(profileRequestContext, authenticationContext, flow);
                        return;
                    }
                } else {
                    log.warn("{} Configuration does not support requested principal evaluation with "
                            + "operator '{}' and type '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                            p.getClass());
                }
            }
        } else if (flow.apply(profileRequestContext)) {
            selectInactiveFlow(profileRequestContext, authenticationContext, flow);
            return;
        }

        log.error("{} Signaled flow {} was not applicable to request", getLogPrefix(), flow.getId());
        ActionSupport.buildEvent(profileRequestContext, authenticationContext.isPassive() ? AuthnEventIds.NO_PASSIVE
                : AuthnEventIds.NO_POTENTIAL_FLOW);
    }

    // Checkstyle: MethodLength|CyclomaticComplexity|ReturnCount ON

    // Checkstyle: ReturnCount OFF
    /**
     * Executes the selection process in the absence of specific requested
     * principals.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     */
    private void doSelectNoRequestedPrincipals(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        log.debug("{} No specific Principals requested", getLogPrefix());

        // Check for initial authentication (valid even in presence of forced
        // authentication).
        if (authenticationContext.getInitialAuthenticationResult() != null
                && authenticationContext.getPotentialFlows().containsKey(
                        authenticationContext.getInitialAuthenticationResult().getAuthenticationFlowId())) {
            selectActiveResult(profileRequestContext, authenticationContext,
                    authenticationContext.getInitialAuthenticationResult());
            return;
        }

        if (authenticationContext.isForceAuthn()) {
            log.debug("{} Forced authentication requested, selecting an inactive flow", getLogPrefix());
            final AuthenticationFlowDescriptor flow = getUnattemptedInactiveFlow(profileRequestContext,
                    authenticationContext);
            if (flow == null) {
                log.info("{} No potential flows left to choose from, authentication failed", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext,
                        authenticationContext.isPassive() ? AuthnEventIds.NO_PASSIVE : AuthnEventIds.NO_POTENTIAL_FLOW);
                return;
            }
            selectInactiveFlow(profileRequestContext, authenticationContext, flow);
            return;
        }

        // Pick a result to reuse if possible.
        for (final AuthenticationResult activeResult : authenticationContext.getActiveResults().values()) {
            final AuthenticationFlowDescriptor flow = authenticationContext.getPotentialFlows().get(
                    activeResult.getAuthenticationFlowId());
            if (flow != null) {
                selectActiveResult(profileRequestContext, authenticationContext, activeResult);
                return;
            }
        }

        log.debug("{} No usable active results available, selecting an inactive flow", getLogPrefix());
        final AuthenticationFlowDescriptor flow = getUnattemptedInactiveFlow(profileRequestContext,
                authenticationContext);
        if (flow == null) {
            log.info("{} No potential flows left to choose from, authentication failed", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext,
                    authenticationContext.isPassive() ? AuthnEventIds.NO_PASSIVE : AuthnEventIds.NO_POTENTIAL_FLOW);
            return;
        }
        selectInactiveFlow(profileRequestContext, authenticationContext, flow);
    }

    // Checkstyle: ReturnCount ON

    /**
     * Return the first inactive potential flow not found in the intermediate
     * flows collection that applies to the request.
     * 
     * @param profileRequestContext
     *            the current profile request context
     * @param authenticationContext
     *            the current authentication context
     * @return an eligible flow, or null
     */
    @Nullable
    private AuthenticationFlowDescriptor getUnattemptedInactiveFlow(
            @Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        for (final AuthenticationFlowDescriptor flow : authenticationContext.getPotentialFlows().values()) {
            if (!authenticationContext.getIntermediateFlows().containsKey(flow.getId())) {
                if (!authenticationContext.isPassive() || flow.isPassiveAuthenticationSupported()) {
                    if (flow.apply(profileRequestContext)) {
                        return flow;
                    }
                }
            }
        }

        return null;
    }

    /**
     * Selects an inactive flow and completes processing.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     * @param descriptor
     *            the flow to select
     */
    private void selectInactiveFlow(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext,
            @Nonnull final AuthenticationFlowDescriptor descriptor) {

        log.debug("{} Selecting inactive authentication flow {}", getLogPrefix(), descriptor.getId());
        authenticationContext.setAttemptedFlow(descriptor);
        ActionSupport.buildEvent(profileRequestContext, descriptor.getId());
    }

    /**
     * Selects an active result and completes processing.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     * @param result
     *            the result to reuse
     */
    private void selectActiveResult(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext, @Nonnull final AuthenticationResult result) {

        log.debug("{} Reusing active result {}", getLogPrefix(), result.getAuthenticationFlowId());
        result.setLastActivityInstantToNow();
        authenticationContext.setAuthenticationResult(result);
        ActionSupport.buildProceedEvent(profileRequestContext);
    }

    /**
     * Executes the selection process in the presence of specific requested
     * Principals, requiring evaluation of potential flows and results for
     * Principal-compatibility with request.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     */
    private boolean doSelectRequestedPrincipals(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        log.debug("{} Specific principals requested with '{}' operator: {}", getLogPrefix(),
                requestedPrincipalCtx.getOperator(), requestedPrincipalCtx.getRequestedPrincipals());

        if (authenticationContext.getInitialAuthenticationResult() != null
                && authenticationContext.getPotentialFlows().containsKey(
                        authenticationContext.getInitialAuthenticationResult().getAuthenticationFlowId())) {
            // Invoke possible SSO but with the initial result as the only
            // possible reuse option.
            return selectRequestedFlow(profileRequestContext, authenticationContext, Collections.singletonMap(
                    authenticationContext.getInitialAuthenticationResult().getAuthenticationFlowId(),
                    authenticationContext.getInitialAuthenticationResult()));
        } else if (authenticationContext.isForceAuthn()) {
            log.debug("{} Forced authentication requested, selecting an inactive flow", getLogPrefix());
            return selectRequestedInactiveFlow(profileRequestContext, authenticationContext);
        } else if (authenticationContext.getActiveResults().isEmpty()) {
            log.debug("{} No active results available, selecting an inactive flow", getLogPrefix());
            return selectRequestedInactiveFlow(profileRequestContext, authenticationContext);
        } else {
            return selectRequestedFlow(profileRequestContext, authenticationContext,
                    authenticationContext.getActiveResults());
        }
    }

    /**
     * Selects an inactive flow in the presence of specific requested
     * Principals, and completes processing.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     */
    private boolean selectRequestedInactiveFlow(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final Map<String, AuthenticationFlowDescriptor> potentialFlows = authenticationContext.getPotentialFlows();

        // Check each flow for compatibility with request. Don't check for an
        // active result also.
        // Also omit anything in the intermediates collection already.
        for (final Principal p : requestedPrincipalCtx.getRequestedPrincipals()) {
            log.debug("{} Checking for an inactive flow compatible with operator '{}' and principal '{}'",
                    getLogPrefix(), requestedPrincipalCtx.getOperator(), p.getName());
            final PrincipalEvalPredicate predicate = requestedPrincipalCtx.getPredicate(p);
            if (predicate != null) {
                for (final AuthenticationFlowDescriptor descriptor : potentialFlows.values()) {
                    if (!authenticationContext.getIntermediateFlows().containsKey(descriptor.getId())
                            && predicate.apply(descriptor) && descriptor.apply(profileRequestContext)) {
                        if (!authenticationContext.isPassive() || descriptor.isPassiveAuthenticationSupported()) {
                            selectInactiveFlow(profileRequestContext, authenticationContext, descriptor);
                            return true;
                        }
                    }
                }
            } else {
                log.warn("{} Configuration does not support requested principal evaluation with "
                        + "operator '{}' and type '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                        p.getClass());
            }
        }

        log.info("{} None of the potential authentication flows can satisfy the request", getLogPrefix());
        return false;
    }

    /**
     * Selects a flow or an active result in the presence of specific requested
     * Principals and completes processing.
     * 
     * @param profileRequestContext
     *            the current IdP profile request context
     * @param authenticationContext
     *            the current authentication context
     * @param activeResults
     *            active results that may be reused
     */
    // Checkstyle: MethodLength|CyclomaticComplexity|ReturnCount OFF
    private boolean selectRequestedFlow(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext,
            @Nonnull @NonnullElements final Map<String, AuthenticationResult> activeResults) {

        if (favorSSO) {
            log.debug("{} Giving priority to active results that meet request requirements");

            // Check each active result for compatibility with request.
            for (final Principal p : requestedPrincipalCtx.getRequestedPrincipals()) {
                log.debug("{} Checking for an active result compatible with operator '{}' and principal '{}'",
                        getLogPrefix(), requestedPrincipalCtx.getOperator(), p.getName());
                final PrincipalEvalPredicate predicate = requestedPrincipalCtx.getPredicate(p);
                if (predicate != null) {
                    for (final AuthenticationResult result : activeResults.values()) {
                        if (predicate.apply(result)) {
                            selectActiveResult(profileRequestContext, authenticationContext, result);
                            return true;
                        }
                    }
                } else {
                    log.warn("{} Configuration does not support requested principal evaluation with "
                            + "operator '{}' and type '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                            p.getClass());
                }
            }

            // We know at this point there are no active results that will fit,
            // so drop into inactive.
            return selectRequestedInactiveFlow(profileRequestContext, authenticationContext);
            // return;

        } else {
            final Map<String, AuthenticationFlowDescriptor> potentialFlows = authenticationContext.getPotentialFlows();

            // In this branch, we check each flow for compatibility *and* then
            // double check to see if an active
            // result from that flow also exists and is compatible. This favors
            // a matching inactive flow that is
            // higher in request precedence than an active result.
            for (final Principal p : requestedPrincipalCtx.getRequestedPrincipals()) {
                log.debug("{} Checking for an inactive flow or active result compatible with "
                        + "operator '{}' and principal '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                        p.getName());
                final PrincipalEvalPredicate predicate = requestedPrincipalCtx.getPredicate(p);
                if (predicate != null) {
                    for (final AuthenticationFlowDescriptor descriptor : potentialFlows.values()) {
                        if (!authenticationContext.getIntermediateFlows().containsKey(descriptor.getId())
                                && predicate.apply(descriptor) && descriptor.apply(profileRequestContext)) {

                            // Now check for an active result we can use from
                            // this flow. Not all results from a flow
                            // will necessarily match the request just because
                            // the flow might.
                            final AuthenticationResult result = activeResults.get(descriptor.getId());
                            if (result == null || !predicate.apply(result)) {
                                if (!authenticationContext.isPassive() || descriptor.isPassiveAuthenticationSupported()) {
                                    selectInactiveFlow(profileRequestContext, authenticationContext, descriptor);
                                    return true;
                                }
                            } else {
                                selectActiveResult(profileRequestContext, authenticationContext, result);
                                return true;
                            }
                        }
                    }
                } else {
                    log.warn("{} Configuration does not support requested principal evaluation with "
                            + "operator '{}' and type '{}'", getLogPrefix(), requestedPrincipalCtx.getOperator(),
                            p.getClass());
                }
            }

            log.info("{} None of the potential authentication flows can satisfy the request", getLogPrefix());
            return false;
        }
    }
    // Checkstyle: MethodLength|CyclomaticComplexity|ReturnCount ON

}