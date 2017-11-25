package org.apache.turbine.flux.tools;

import java.util.List;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.fulcrum.security.acl.AccessControlList;
import org.apache.fulcrum.security.entity.Group;
import org.apache.fulcrum.security.entity.Permission;
import org.apache.fulcrum.security.entity.Role;
import org.apache.fulcrum.security.torque.om.TurbineUserPeer;
import org.apache.fulcrum.security.util.GroupSet;
import org.apache.fulcrum.security.util.PermissionSet;
import org.apache.fulcrum.security.util.RoleSet;
import org.apache.torque.criteria.Criteria;
import org.apache.turbine.annotation.TurbineConfiguration;
import org.apache.turbine.annotation.TurbineService;
import org.apache.turbine.om.security.User;
import org.apache.turbine.services.pull.ApplicationTool;
import org.apache.turbine.services.pull.RunDataApplicationTool;
import org.apache.turbine.services.security.SecurityService;
import org.apache.turbine.util.RunData;
import org.apache.turbine.util.template.SelectorBox;

/**
 * The pull api for flux templates
 *
 * @version $Id: FluxTool.java,v 1.13 2017/11/16 11:24:41 painter Exp $
 */
public class FluxTool implements ApplicationTool, RunDataApplicationTool {

	/** Injected service instance */
	@TurbineService
	private SecurityService security;

	/** Injected configuration instance */
	@TurbineConfiguration
	private Configuration conf;

	/** The object containing request specific data */
	private RunData data;

	/** A Group object for use within the Flux API. */
	private Group group = null;

	/** A Issue object for use within the Flux API. */
	private Role role = null;

	/** A Permission object for use within the Flux API. */
	private Permission permission = null;

	/** A User object for use within the Flux API. */
	private User user = null;

	@Override
	public void init(Object data) {
		this.data = (RunData) data;
	}

	/**
	 * Constructor does initialization stuff
	 */
	public FluxTool() {

	}

	public Group getGroup() throws Exception {
		String name = data.getParameters().getString("name");
		if (StringUtils.isEmpty(name)) {
			group = security.getGroupInstance();
		} else {
			group = security.getGroupByName(name);
		}
		return group;
	}

	public String getMode() {
		return data.getParameters().getString("mode");
	}

	public GroupSet getGroups() throws Exception {
		return security.getAllGroups();
	}

	public Role getRole() throws Exception {
		String name = data.getParameters().getString("name");
		if (StringUtils.isEmpty(name)) {
			role = security.getRoleInstance();
		} else {
			role = security.getRoleByName(name);
		}
		return role;
	}

	/**
	 */
	public RoleSet getRoles() throws Exception {
		return security.getAllRoles();
	}

	public Permission getPermission() throws Exception {
		if (permission == null) {
			String name = data.getParameters().getString("name");
			if (name == null || name.length() == 0) {
				permission = security.getPermissionInstance(null);
			} else {
				permission = security.getPermissionByName(name);
			}
		}
		return permission;
	}

	/**
	 * Get all permissions.
	 */
	public PermissionSet getPermissions() throws Exception {
		return security.getAllPermissions();
	}

	public User getUser() throws Exception {
		String name = data.getParameters().getString("username");
		if (StringUtils.isEmpty(name)) {
			user = security.getUserInstance();
		} else {
			user = security.getUser(name);
		}
		return user;
	}

	public AccessControlList getACL() throws Exception {
		// Get the Turbine ACL implementation
		return security.getUserManager().getACL(getUser());
	}

	/**
	 */
	public SelectorBox getFieldList() throws Exception {
		Object[] names = { "username", "firstname", "middlename", "lastname" };
		Object[] values = { "Username", "First Name", "Middle Name", "Last Name" };
		return new SelectorBox("fieldList", names, values);
	}

	/**
	 */
	public SelectorBox getUserFieldList() throws Exception {
		/**
		 * This is a tie to the DB implementation something should be added the
		 * pluggable pieces to allow decent parameterized searching.
		 */

		Object[] names = { TurbineUserPeer.LOGIN_NAME, TurbineUserPeer.FIRST_NAME, TurbineUserPeer.LAST_NAME };

		Object[] values = { "User Name", "First Name", "Last Name" };

		return new SelectorBox("fieldList", names, values);
	}

	/**
	 * Select all the users and place them in an array that can be used within the
	 * UserList.vm template.
	 */
	@SuppressWarnings("unchecked")
	public List<User> getUsers() throws Exception {
		Criteria criteria = new Criteria();
		String fieldList = data.getParameters().getString("fieldList");

		if (fieldList != null) {
			// This is completely database centric.
			String searchField = data.getParameters().getString("searchField");
			criteria.where(fieldList, searchField, Criteria.LIKE);
		}

		return (List<User>) security.getUserManager().retrieveList(criteria);
	}

	@Override
	public void refresh(RunData data) {
		this.data = data;
	}

	@Override
	public void refresh() {
		// nothing to do here
	}

}
