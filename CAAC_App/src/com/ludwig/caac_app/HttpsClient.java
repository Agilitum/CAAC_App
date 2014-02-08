package com.ludwig.caac_app;

import java.io.InputStream;
import java.security.KeyStore;

import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;

import android.content.Context;

public class HttpsClient extends DefaultHttpClient {

	final Context context;
	
	public HttpsClient(Context context){
		this.context = context;
	}
	
	@Override
	protected ClientConnectionManager createClientConnectionManager() {
		SchemeRegistry registry = new SchemeRegistry();
		registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
		
		// register for port 443 the custom SSLSocketFactory with custom
		// keystore to the ConnectionsManager
		registry.register(new Scheme("https", newCustomSSLSocketFactory(), 443));
		return new SingleClientConnManager(getParams(), registry);
	}
	
	private SSLSocketFactory newCustomSSLSocketFactory() {
		try{
			// get a bouncy castle keystore (.bks) format instance
			KeyStore trusted = KeyStore.getInstance("BKS");
			
			// get the raw resource which constains the certificate
			InputStream in = context.getResources().openRawResource(R.raw.mykeystore);
			
			try{
				// initialise keystore with trusted certificates 
				// & provide password for keystore
				trusted.load(in, "my_password".toCharArray());
			} finally {
				in.close();
			}
			// pass keystore to SSLSocketFactory
			SSLSocketFactory socketFactory = new SSLSocketFactory(trusted);
			
			// verificate hostname from certificate
			socketFactory.setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
			return socketFactory;
		} catch (Exception e) {
			throw new AssertionError(e);
		}
	}
}
