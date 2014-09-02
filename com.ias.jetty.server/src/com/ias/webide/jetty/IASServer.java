package com.ias.webide.jetty;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.Properties;

import org.eclipse.core.resources.IWorkspace;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.jetty.deploy.DeploymentManager;
import org.eclipse.jetty.deploy.PropertiesConfigurationManager;
import org.eclipse.jetty.deploy.providers.WebAppProvider;
import org.eclipse.jetty.jaas.JAASLoginService;
import org.eclipse.jetty.jmx.MBeanContainer;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.security.jaspi.JaspiAuthenticatorFactory;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LowResourceMonitor;
import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.eclipse.jetty.util.thread.ScheduledExecutorScheduler;
import org.eclipse.jetty.webapp.WebAppContext;
import com.ias.webide.jetty.handlers.ProjectHandler;

public class IASServer {
	/*
	 * Testing
	 */
	private SecurityHandler constraintSecurityHandler;

	private String jetty_home;
	private String webbapp_home;

	private Server server;

	private HttpConfiguration http_config;

	public static void main(String[] args) throws Exception {
		pluginStart();
	}

	public static void mainStart() throws Exception {
		IASServer iasServer = new IASServer();
		iasServer.loadSystemProperties("config.properties");
		ContextHandlerCollection contexts = iasServer.configure();
		iasServer.fullWebAppDeployment(contexts);
		// iasServer.setLoginService(contexts);
		iasServer.start();
		iasServer.join();
	}

	public static void pluginStart() throws Exception {
		IASServer iasServer = new IASServer();
		iasServer.loadSystemProperties("config.properties");
		iasServer.configureHttp();
		iasServer.configureHttps();
		// ContextHandlerCollection contexts = iasServer.configure();
		// iasServer.fullWebAppDeployment(contexts);

		// find project
		String projectPath = "/home/jchardis/git/WebIDE/WebIDE";
		iasServer.addWebApp(projectPath + File.separator + "WebContent", "/WebIDE");
		// iasServer.addWebApp(projectPath);

		iasServer.start();
	}

	public void helper() {

	}

	public IASServer() {
		QueuedThreadPool threadPool = new QueuedThreadPool();
		threadPool.setMaxThreads(500);
		server = new Server(threadPool);
	}

	// public IASServer(String jetty_home, String webbapp_home) {
	// QueuedThreadPool threadPool = new QueuedThreadPool();
	// threadPool.setMaxThreads(500);
	// server = new Server(threadPool);
	// this.jetty_home = jetty_home;
	// this.webbapp_home = webbapp_home;
	// }

	public ContextHandlerCollection configure() throws IOException {
		server.addBean(new ScheduledExecutorScheduler());
		HandlerCollection handlers = new HandlerCollection();
		ContextHandlerCollection contexts = new ContextHandlerCollection();
		handlers.setHandlers(new Handler[] { contexts, new DefaultHandler() });
		server.setHandler(handlers);
		server.setDumpAfterStart(false);
		server.setDumpBeforeStop(false);
		server.setStopAtShutdown(true);
		MBeanContainer mbContainer = new MBeanContainer(ManagementFactory.getPlatformMBeanServer());
		server.addBean(mbContainer);

		configureHttp();
		configureHttps();

		StatisticsHandler stats = new StatisticsHandler();
		stats.setHandler(server.getHandler());
		server.setHandler(stats);
		NCSARequestLog requestLog = new NCSARequestLog();
		requestLog.setFilename(jetty_home + "/logs/yyyy_mm_dd.request.log");
		requestLog.setFilenameDateFormat("yyyy_MM_dd");
		requestLog.setRetainDays(90);
		requestLog.setAppend(true);
		requestLog.setExtended(true);
		requestLog.setLogCookies(false);
		requestLog.setLogTimeZone("GMT");
		RequestLogHandler requestLogHandler = new RequestLogHandler();
		requestLogHandler.setRequestLog(requestLog);
		handlers.addHandler(requestLogHandler);
		LowResourceMonitor lowResourcesMonitor = new LowResourceMonitor(server);
		lowResourcesMonitor.setPeriod(1000);
		lowResourcesMonitor.setLowResourcesIdleTimeout(200);
		lowResourcesMonitor.setMonitorThreads(true);
		lowResourcesMonitor.setMaxConnections(0);
		lowResourcesMonitor.setMaxMemory(0);
		lowResourcesMonitor.setMaxLowResourcesTime(5000);
		server.addBean(lowResourcesMonitor);
		return contexts;

	}

	public void configureHttp() {
		http_config = new HttpConfiguration();
		http_config.setSecureScheme("https");
		http_config.setSecurePort(8443);
		http_config.setOutputBufferSize(32768);
		http_config.setRequestHeaderSize(8192);
		http_config.setResponseHeaderSize(8192);
		http_config.setSendServerVersion(true);
		http_config.setSendDateHeader(false);

		ServerConnector http = new ServerConnector(server, new HttpConnectionFactory(http_config));
		http.setPort(8080);
		http.setIdleTimeout(30000);
		server.addConnector(http);
	}

	public void configureHttps() {
		SslContextFactory sslContextFactory = new SslContextFactory();
		sslContextFactory.setKeyStorePath(jetty_home + "/etc/keystore");
		sslContextFactory.setKeyStorePassword("OBF:1vny1zlo1x8e1vnw1vn61x8g1zlu1vn4");
		sslContextFactory.setKeyManagerPassword("OBF:1u2u1wml1z7s1z7a1wnl1u2g");
		sslContextFactory.setTrustStorePath(jetty_home + "/etc/keystore");
		sslContextFactory.setTrustStorePassword("OBF:1vny1zlo1x8e1vnw1vn61x8g1zlu1vn4");
		sslContextFactory.setExcludeCipherSuites("SSL_RSA_WITH_DES_CBC_SHA", "SSL_DHE_RSA_WITH_DES_CBC_SHA", "SSL_DHE_DSS_WITH_DES_CBC_SHA", "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
				"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA", "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA");

		HttpConfiguration https_config = new HttpConfiguration(http_config);
		https_config.addCustomizer(new SecureRequestCustomizer());
		ServerConnector sslConnector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https_config));
		sslConnector.setPort(8443);
		server.addConnector(sslConnector);
	}

	public void addWebApp(String warPath, String contextPath) throws IOException {
		// Setup JMX
		MBeanContainer mbContainer = new MBeanContainer(ManagementFactory.getPlatformMBeanServer());
		server.addBean(mbContainer);

		WebAppContext webapp = new WebAppContext();
		IWorkspace workspace = ResourcesPlugin.getWorkspace();
		ProjectHandler handler = new ProjectHandler(workspace);
		handler.setContextPath("/test/");
		webapp.setContextPath(contextPath);
		webapp.setWar(warPath);
		// webapp.setHandler(handler);

		HandlerList handlers = new HandlerList();
		handlers.setHandlers(new Handler[] { handler, webapp, new DefaultHandler() });
		// webapp.setHandler(handler);
		// server.setHandler(handler);

		// server.setHandler(webapp);
		server.setHandler(handlers);
		// webapp.setHandler(handler);
	}

	public void example() {
		// ContextHandler context0 = new ContextHandler();
		// context0.setContextPath("/");
		// ResourceHandler rh0 = new ResourceHandler();
		// rh0.setBaseResource(Resource.newResource(MavenTestingUtils.getTestResourceDir("dir0")));
		// context0.setHandler(rh0);
		// ContextHandler context1 = new ContextHandler();
		// context1.setContextPath("/");
		// ResourceHandler rh1 = new ResourceHandler();
		// rh1.setBaseResource(Resource.newResource(MavenTestingUtils.getTestResourceDir("dir1")));
		// context1.setHandler(rh1);
		// ContextHandlerCollection contexts = new ContextHandlerCollection();
		// contexts.setHandlers(new Handler[] { context0, context1 });
		// server.setHandler(contexts);
		// server.start();
		// System.err.println(server.dump());
		// server.join();
	}

	// public void addWebApps(ContextHandlerCollection contexts) {
	// // WebAppContext wdWebapp = new WebAppContext();
	// // wdWebapp.setContextPath("/webdesigner");
	// // wdWebapp.setWar("/home/jchardis/git/IAS-WebDesigner/WebDesigner");
	// // wdWebapp.setHandler(constraintSecurityHandler);
	// // server.addBean(wdWebapp);
	// }

	public void setLoginService(ContextHandlerCollection contexts) {
		JaspiAuthenticatorFactory authenticatorFactory = new JaspiAuthenticatorFactory();
		constraintSecurityHandler = new ConstraintSecurityHandler();
		constraintSecurityHandler.setHandler(contexts);
		constraintSecurityHandler.setAuthenticatorFactory(authenticatorFactory);
		constraintSecurityHandler.setAuthenticator(new BasicAuthenticator());
		JAASLoginService ls = new JAASLoginService("jdbc");
		ls.setLoginModuleName("jdbc");
		DefaultIdentityService defaultIdentityService = new DefaultIdentityService();
		ls.setIdentityService(defaultIdentityService);
		constraintSecurityHandler.setLoginService(ls);
		authenticatorFactory.setLoginService(ls);
		server.setHandler(constraintSecurityHandler);
	}

	public void fullWebAppDeployment(ContextHandlerCollection contexts) {
		addDeployer(webbapp_home, contexts);
		// addDeployer("/home/jchardis/git/IAS-WebDesigner/", contexts);
	}

	public void addDeployer(String directory, ContextHandlerCollection contexts) {
		DeploymentManager deployer = new DeploymentManager();
		deployer.setContexts(contexts);
		deployer.setContextAttribute("org.eclipse.jetty.server.webapp.ContainerIncludeJarPattern", ".*/servlet-api-[^/]*\\.jar$");
		WebAppProvider webapp_provider = new WebAppProvider();
		webapp_provider.setMonitoredDirName(directory);
		// webapp_provider.setDefaultsDescriptor(jetty_home
		// + "/etc/webdefault.xml");
		webapp_provider.setScanInterval(100);
		webapp_provider.setExtractWars(false);
		webapp_provider.setConfigurationManager(new PropertiesConfigurationManager());
		deployer.addAppProvider(webapp_provider);
		server.addBean(deployer);
	}

	public void setWebAppContext(WebAppContext context) {
		server.setHandler(context);
	}

	public void start() throws Exception {
		server.start();
	}

	public void join() throws InterruptedException {
		server.join();
	}

	public boolean isRunning() {
		return server.isRunning();
	}

	public void stop() throws Exception {
		server.stop();
	}

	public void loadSystemProperties(String path) throws IOException {
		ConfigPropertiesUtil configPropertiesUtil = new ConfigPropertiesUtil();
		configPropertiesUtil.resolveProperties(new File(path));

		FileInputStream propFile = new FileInputStream(path);
		Properties p = new Properties(System.getProperties());
		p.load(propFile);
		System.setProperties(p);
		jetty_home = System.getProperty("jetty.home", null);
		webbapp_home = System.getProperty("webapp.home", null);
		System.out.println("WebAppHome: " + webbapp_home);
		System.out.println("JettyHome: " + jetty_home);
	}

	public String getJetty_home() {
		return jetty_home;
	}

	public void setJetty_home(String jetty_home) {
		this.jetty_home = jetty_home;
	}

	public String getWebbapp_home() {
		return webbapp_home;
	}

	public void setWebbapp_home(String webbapp_home) {
		this.webbapp_home = webbapp_home;
	}

	public Server getServer() {
		return server;
	}

	public void setServer(Server server) {
		this.server = server;
	}

	public long getStopTimeout() {
		return server.getStopTimeout();
	}

}