package com.ias.webide.jetty;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Stack;

/**
 * Used to read properties files and to reuse properties
 * 
 * @author jchardis
 * 
 */
public class ConfigPropertiesUtil {

	public ConfigPropertiesUtil() {
	}

	/**
	 * Returns the properties read from a file.
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public Properties readProperties(File file) throws IOException {
		FileInputStream propFile = new FileInputStream(file);
		Properties properties = new Properties();
		return properties;
	}

	/**
	 * Resolves properties from a file and adds them to system properties
	 * 
	 * @param file
	 * @return
	 * @throws IOException
	 */
	public Properties resolveProperties(File file) throws IOException {
		FileInputStream propFile = new FileInputStream(file);
		Properties properties = new Properties();
		Properties newProperties = new Properties();
		Enumeration<?> keys = properties.propertyNames();
		while (keys.hasMoreElements()) {
			String key = (String) keys.nextElement();
			String oldProperty = properties.getProperty(key);
			String newProperty = resolve(oldProperty);
			System.setProperty(key, newProperty);
			newProperties.setProperty(key, newProperty);
		}
		return newProperties;
	}

	/**
	 * Resolves string by replacing referenced keys with their property value
	 * 
	 * @param string
	 * @return
	 * @throws IllegalArgumentException
	 */
	public String resolve(String string) throws IllegalArgumentException {
		StringBuffer sb = new StringBuffer();
		Stack<StringBuffer> stack = new Stack<StringBuffer>();
		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			switch (c) {
			case '$':
				if (i + 1 < string.length() && string.charAt(i + 1) == '{') {
					stack.push(sb);
					sb = new StringBuffer();
					i++;
				}
				break;
			case '}':
				if (stack.isEmpty())
					throw new IllegalArgumentException("unexpected '}'");
				String name = sb.toString();
				sb = stack.pop();
				sb.append(System.getProperty(name, null));
				break;
			default:
				sb.append(c);
				break;
			}
		}
		if (!stack.isEmpty())
			throw new IllegalArgumentException("expected '}'");
		return sb.toString();
	}

}