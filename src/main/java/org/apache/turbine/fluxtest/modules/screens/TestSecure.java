package org.apache.turbine.fluxtest.modules.screens;


import java.util.ArrayList;
import java.util.List;
import org.apache.torque.criteria.Criteria;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.velocity.context.Context;

/**
 * This class provides the data required for displaying content in the
 * Velocity page. 
 */
public class TestSecure extends SecureScreen
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
      context.put("success", "Congratulations, it worked here too!");
    }
}
