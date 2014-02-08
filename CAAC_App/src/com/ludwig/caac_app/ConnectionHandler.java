package com.ludwig.caac_app;

import android.app.Activity;
import android.content.Context;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.telephony.TelephonyManager;

/**
 * This class is meant to pass a connectionRequest to the CAAC wrapping all essential data.
 * @author Ludwig
 *
 */
public class ConnectionHandler extends Activity {

	// constructor
	public ConnectionHandler(){

	}
	// create telephony manager to access telephone specific status
	TelephonyManager mngr = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE); 
	
	// get IMEI --> only for telephones
	public String getIMEI(){
		
		return mngr.getDeviceId();
	}
	
	//get session token
	public int sessionToken(){
		return (int) Math.random();
	}
	
	// get if phone is in roaming
	public Boolean phoneInRoamingMode(){
		boolean isRoaming= mngr.isNetworkRoaming();
		if(isRoaming)
			return true;
		else
			return false;
	}

	// get network country code
	public String countryCode(){
		return mngr.getNetworkCountryIso();
	}
    
	// check current WiFi connection
	public String getCurrentWiFiSSID(Context context){
		WifiManager wifiMngr = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
		WifiInfo wifiInfo = wifiMngr.getConnectionInfo();
		if (WifiInfo.getDetailedStateOf(wifiInfo.getSupplicantState()) == NetworkInfo.DetailedState.CONNECTED) {
			String ssid = wifiInfo.getSSID();
			return ssid;
		}
		return null;
	}
	

}
