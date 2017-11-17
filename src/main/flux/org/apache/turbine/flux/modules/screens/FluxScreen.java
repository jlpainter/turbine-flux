package org.apache.turbine.flux.modules.screens;

import org.apache.commons.configuration.Configuration;
import org.apache.fulcrum.security.model.turbine.TurbineAccessControlList;
import org.apache.turbine.Turbine;
import org.apache.turbine.TurbineConstants;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.modules.screens.VelocitySecureScreen;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.velocity.context.Context;

/**
 * Base screen for secure web acces to the storage side of Tambora.
 *
 */
public abstract class FluxScreen extends VelocitySecureScreen {

	@TurbineService
	protected SecurityService securityService;

	@TurbineConfiguration(TurbineConstants.TEMPLATE_LOGIN)
	private Configuration templateLogin;

	@TurbineConfiguration(TurbineConstants.TEMPLATE_HOMEPAGE)
	private Configuration templateHomepage;

	/**
	 * This method is called by Turbine
	 */
	@Override
	protected void doBuildTemplate(PipelineData data, Context context) throws Exception {

		/*
		 * Check to see if the embedded menu should be displayed in the templates.
		 */
		if (Turbine.getConfiguration().getBoolean("flux.embedded.show.menu", false)) {
			context.put("showEmbeddedMenu", true);
		}

		/*
		 * Check to see if we will display the finders on the forms used in Flux.
		 */
		if (Turbine.getConfiguration().getBoolean("flux.ui.show.finder", false)) {
			context.put("showFinder", true);
		}

	}

	@Override
	protected boolean isAuthorized(PipelineData data) throws Exception {
		boolean isAuthorized = false;

		/*
		 * Grab the Flux Admin role listed in the Flux.properties file that is included
		 * in the the standard TurbineResources.properties file.
		 */
		String fluxAdminRole = Turbine.getConfiguration().getString("flux.admin.role");

		// Get the Turbine ACL implementation
		TurbineAccessControlList acl = getRunData(data).getACL();

		if (acl == null) {
			// commons configuration getProperty: prefix removed, the key for the value ..
			// is an empty string, the result an object
			getRunData(data).setScreenTemplate((String) templateLogin.getProperty(""));
			isAuthorized = false;
		} else if (acl.hasRole(fluxAdminRole)) {
			isAuthorized = true;
		} else {
			getRunData(data).setScreenTemplate((String) templateHomepage.getProperty(""));
			getRunData(data).setMessage("You do not have access to this part of the site.");
			isAuthorized = false;
		}
		return isAuthorized;
	}
}
