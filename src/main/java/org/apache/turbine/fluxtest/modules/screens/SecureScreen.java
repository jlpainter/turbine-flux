package org.apache.turbine.fluxtest.modules.screens;



import org.apache.fulcrum.security.model.turbine.TurbineAccessControlList;
import org.apache.turbine.Turbine;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.modules.screens.VelocitySecureScreen;
import org.apache.turbine.om.security.User;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.velocity.context.Context;
import org.apache.commons.configuration.Configuration;

/**
 * This class provides a sample implementation for creating a secured screen
 */
public class SecureScreen extends VelocitySecureScreen 
{
   	@TurbineService
   	protected SecurityService securityService;
    	
    @TurbineConfiguration( TurbineConstants.TEMPLATE_LOGIN )
    private Configuration templateLogin;
    
    @TurbineConfiguration( TurbineConstants.TEMPLATE_HOMEPAGE )
    private Configuration templateHomepage;
    
    @Override
    protected boolean isAuthorized(PipelineData data) throws Exception 
    {
        boolean isAuthorized = false;
    
        // Who is our current user?
        User user = getRunData(data).getUser();
        
        // Get the Turbine ACL implementation
        TurbineAccessControlList acl = getRunData(data).getACL();
        
        if (acl == null)
        {
          // commons configuration getProperty: prefix removed, the key for the value .. is an empty string, the result an object
        getRunData(data).setScreenTemplate( (String) templateLogin.getProperty("") );
        	isAuthorized = false;
        } 
        else if (acl.hasRole("turbineuser") || acl.hasRole("turbineadmin"))
        {
            isAuthorized = true;
        }
        else 
        {
            getRunData(data).setScreenTemplate( (String) templateHomepage.getProperty("") );
            getRunData(data).setMessage("You do not have access to this part of the site.");
            isAuthorized = false;
        }
        return isAuthorized;
    }

    /**
     * Implement this to add information to the context.
     *
     * @param data
     *            Turbine information.
     * @param context
     *            Context for web pages.
     * @exception Exception,
     *                a generic exception.
     */
    @Override
    protected void doBuildTemplate(PipelineData data, Context context) throws Exception 
    {
    
    }
}
