package org.apache.turbine.fluxtest.modules.actions;

import org.apache.fulcrum.security.util.PasswordMismatchException;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.om.security.User;
import org.apache.turbine.pipeline.PipelineData;
import org.apache.turbine.services.security.SecurityService;
import org.apache.turbine.util.RunData;
import org.apache.velocity.context.Context;

/**
 * Change Password action.
 *
 */
public class ChangePasswordAction extends SecureAction

{

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	@Override
	public void doPerform(PipelineData data, Context context) throws Exception {
		log.info("event not found!");
	}

	public void doUpdate(PipelineData data, Context context) throws Exception {

		User user = getRunData(data).getUser();

		RunData rundata = getRunData(data);
		String oldPassword = rundata.getParameters().getString("oldpassword", "");
		String newPassword = rundata.getParameters().getString("newpassword", "");

		try {
			security.changePassword(user, oldPassword, newPassword);
			rundata.setMessage("Password changed!");
		} catch (PasswordMismatchException e) {
			rundata.setMessage(e.getMessage());
			rundata.setScreenTemplate("Password.vm");
		}

	}


}
