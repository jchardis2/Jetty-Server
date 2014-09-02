package com.ias.webide.jetty.handlers;

import org.eclipse.core.resources.IWorkspace;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.jetty.server.handler.ContextHandler;

public abstract class AbstractWebIDEHandler extends ContextHandler {
	public IWorkspace workspace = ResourcesPlugin.getWorkspace();

	public AbstractWebIDEHandler(IWorkspace workspace) {
		this.workspace = workspace;
	}
}
