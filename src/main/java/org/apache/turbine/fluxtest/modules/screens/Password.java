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
 * This class provides a sample extending a secured screen
 */
public class Password extends SecureScreen 
{
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
    	
    }
}
