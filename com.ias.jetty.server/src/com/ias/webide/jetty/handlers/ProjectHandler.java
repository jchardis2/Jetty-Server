package com.ias.webide.jetty.handlers;

import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.core.resources.IWorkspace;
import org.eclipse.jetty.server.Request;

@WebServlet(urlPatterns = { "/project" })
public class ProjectHandler extends AbstractWebIDEHandler {

	public ProjectHandler(IWorkspace workspace) {
		super(workspace);
	}

	@Override
	public void setContextPath(String arg0) {
		super.setContextPath("/projects");
	};

	// public void handle(String arg0, Request arg1, HttpServletRequest arg2,
	// HttpServletResponse arg3) throws IOException, ServletException {
	// PluginFileResolver fileResolver = new PluginFileResolver();
	// try {
	// String path = fileResolver.getAbsolutePath("config.properties");
	// // System.out.println(path);
	// } catch (URISyntaxException e) {
	// // TODO Auto-generated catch block
	// e.printStackTrace();
	// }
	// }
	@Override
	public void doHandle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) {
		Enumeration<String> paramNames = request.getParameterNames();
		while (paramNames.hasMoreElements()) {
			String action = paramNames.nextElement();
//			if (action.startsWith("webide_")) {
				System.out.println(action + ": " + request.getParameter(action));
//			}
		}
	}
}
