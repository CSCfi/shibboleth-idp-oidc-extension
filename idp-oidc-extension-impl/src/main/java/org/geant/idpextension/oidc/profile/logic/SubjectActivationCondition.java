
package org.geant.idpextension.oidc.profile.logic;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import com.google.common.base.Predicate;

/**
 * Activation condition returning true if subject cannot be located from oidc response context. This may be applied
 * preventing the subject resolving in token and userinfo endpoints as it is unnecessary. The activation condition may
 * be used with other protocols also, returning always true.
 */
@SuppressWarnings("rawtypes")
public class SubjectActivationCondition implements Predicate<ProfileRequestContext> {

    @Override
    public boolean apply(ProfileRequestContext input) {
        final MessageContext outboundMessageCtx = input.getOutboundMessageContext();
        if (outboundMessageCtx == null) {
            return true;
        }
        OIDCAuthenticationResponseContext oidcResponseContext =
                outboundMessageCtx.getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (oidcResponseContext == null) {
            return true;
        }
        return oidcResponseContext.getSubject() == null;
    }

}
