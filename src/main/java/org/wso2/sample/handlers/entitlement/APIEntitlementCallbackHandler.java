package org.wso2.sample.handlers.entitlement;

import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.RESTConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityUtils;
import org.wso2.carbon.apimgt.gateway.handlers.security.AuthenticationContext;
import org.wso2.carbon.identity.entitlement.mediator.callback.EntitlementCallbackHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.entitlement.proxy.Attribute;



public class APIEntitlementCallbackHandler extends EntitlementCallbackHandler {
	private static final Log log = LogFactory.getLog(APIEntitlementCallbackHandler.class);

    public String getUserName(MessageContext synCtx) {
        AuthenticationContext authContext = APISecurityUtils.getAuthenticationContext(synCtx);
        String userName = null;
        if (authContext != null) {
            userName = authContext.getUsername();

        }
        log.debug("UserName ---"+userName);
        return userName;
    }

	public String findServiceName(MessageContext synCtx) {
		String path = ((String) synCtx.getProperty(RESTConstants.REST_SUB_REQUEST_PATH));
		log.debug("SERVICE - REST SUB REQUEST ---"+path);
		return path;

	}

	public String findAction(MessageContext synCtx) {
		log.debug("Operation Name ---"+(String)((Axis2MessageContext) synCtx).getAxis2MessageContext().getProperty(org.apache.axis2.Constants.Configuration.HTTP_METHOD));
		return (String)((Axis2MessageContext) synCtx).getAxis2MessageContext().getProperty(org.apache.axis2.Constants.Configuration.HTTP_METHOD);

	}

	public String findOperationName(MessageContext synCtx) {
		return null;
    }

	public String[] findEnvironment(MessageContext synCtx) {
        return null;
    }


	public Attribute[] findOtherAttributes(MessageContext synCtx)
	{
		log.debug("Custom attribute");
		AuthenticationContext authContext = APISecurityUtils.getAuthenticationContext(synCtx);
		Attribute attributeId = new Attribute("urn:oasis:names:tc:xacml:3.0:attribute-category:custom", "urn:oasis:names:tc:xacml:1.0:application:application-id", "string", authContext.getApplicationName());
		Attribute []attributes = new Attribute[1];
		attributes[0] = attributeId;
		return attributes;
	}
}
