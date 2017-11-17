package org.apache.turbine.fluxtest.modules.screens;


import org.apache.fulcrum.json.JsonService;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.TurbineServices;
import org.apache.velocity.context.Context;
import org.apache.turbine.modules.screens.VelocitySecureScreen;


/**
 * This class provides the data required for displaying content in the
 * Velocity page. 
 */
public class Index extends VelocitySecureScreen
{
    
    JsonService jsonService = (JsonService)TurbineServices.getInstance().getService(JsonService.ROLE);
    /**
     * This method is called by the Turbine framework when the
     * associated Velocity template, Index.vm is requested
     * 
     * @param data the Turbine request data
     * @param context the Velocity context
     * @throws Exception a generic Exception
     */
    @Override
    protected void doBuildTemplate(PipelineData data, Context context)
    		throws Exception
    {
    	context.put("success", "Congratulations, it worked!");
    }
    
    /**
     * This method is called bythe Turbine framework to determine if
     * the current user is allowed to use this screen. If this method
     * returns false, the doBuildTemplate() method will not be called.
     * If a redirect to some "access denied" page is required, do the
     * necessary redirect here.
     * 
     * return always <code>true</code>true, to show this screen as default
     */
    @Override
    protected boolean isAuthorized(PipelineData data) throws Exception
    {
    	// use data.getACL() 
    	return true;
    }
}
