package com.ludwig.caac_app.slidingmenu;

import java.util.ArrayList;

import android.app.Activity;
import android.app.FragmentManager;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.support.v4.app.ActionBarDrawerToggle;
import android.support.v4.app.Fragment;
import android.support.v4.widget.DrawerLayout;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

import com.ludwig.caac_app.R;
import com.ludwig.caac_app.slideingmenu.adapter.NavDrawerListAdapter;
import com.ludwig.caac_app.slidingmenu.model.NavDrawerItem;

public class MainSliderActivity extends Activity {

	private DrawerLayout mDrawerLayout;
	private ListView mDrawerList;
	private ActionBarDrawerToggle mDrawerToggle;
	
	// navigation drawer title
	private CharSequence mDrawerTitle;
	
	// app title
	private CharSequence mTitle;
	
	// slide menu items
	private String[] navMenuTitles;
	private TypedArray navMenuIcons;
	
	private ArrayList<NavDrawerItem> navDrawerItems;
	private NavDrawerListAdapter adapter;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main_slider);
		
		mTitle = mDrawerTitle = getTitle();
		
		// load the slide menu items
		navMenuTitles = getResources().getStringArray(R.array.nav_drawer_items);
		
		// nav drawer icons from resources
		navMenuIcons = getResources().obtainTypedArray(R.array.nav_drawer_icons);
		
		mDrawerLayout = (DrawerLayout) findViewById(R.id.drawer_layout);
		mDrawerList = (ListView) findViewById(R.id.list_slidermenu);
		
		navDrawerItems = new ArrayList<NavDrawerItem>();
		
		// add nav drawer items to the array
		//Home
		navDrawerItems.add(new NavDrawerItem(navMenuTitles[0], navMenuIcons.getResourceId(0, -1)));
		// Email
		navDrawerItems.add(new NavDrawerItem(navMenuTitles[1], navMenuIcons.getResourceId(1, -1)));
		// Browser
		navDrawerItems.add(new NavDrawerItem(navMenuTitles[2], navMenuIcons.getResourceId(2, -1)));
		// Settings
		navDrawerItems.add(new NavDrawerItem(navMenuTitles[3], navMenuIcons.getResourceId(3, -1)));
		
		// recycle the typed array
		navMenuIcons.recycle();
		
		// set nav drawer list adapter
		adapter = new NavDrawerListAdapter(getApplicationContext(), navDrawerItems);
		
		mDrawerList.setAdapter(adapter);
		
		// enabling action bar app icon and make it a toggle button
		getActionBar().setDisplayHomeAsUpEnabled(true);
		getActionBar().setHomeButtonEnabled(true);
		
		mDrawerToggle = new ActionBarDrawerToggle(this, mDrawerLayout,
				R.drawable.ic_drawer,
				R.string.app_name,
				R.string.app_name)
		{
			public void onDrawerClosed(View view){
				getActionBar().setTitle(mTitle);
				// call onPrepareOptionsMenu() to show action bar icons
				invalidateOptionsMenu();
			}
			
			public void onDrawerOpended(View drawerView){
				getActionBar().setTitle(mDrawerTitle);
				// call onPrepareOptionsMenu() to hide action bar icons
				invalidateOptionsMenu();
			}
		};
		mDrawerLayout.setDrawerListener(mDrawerToggle);
		
		if(savedInstanceState == null){
			// on first time display view for first nav item
			displayView(0);
		}
	}

	/**
	 * slide menu itme click listner
	 */
/*	private class SlideMenuClickListener implements ListView.onItemClickListner {
		@Override
		public void onItemClick(AdapterView<?> parent, View view, int position, long id){
			//display view for selected nav drawer item
			displayView(position);
		}
	}
*/	
	/**
	 * display fragment for the selected nav drawer list item
	 */
	private void displayView(int position){
		// update the main content by replacing fragments
		Fragment fragment = null;
		switch(position){
		case 0:
			fragment = new HomeFragment();
			break;
		case 1:
			fragment = new EmailFragment();
			break;
		case 2:
			fragment = new WebFragment();
			break;
		case 3:
			fragment = new SettingsFragment();
			break;
		default:
			break;
		}
		
        if (fragment != null) {
            FragmentManager fragmentManager = getFragmentManager();
            fragmentManager.beginTransaction().replace(R.id.frame_container, fragment).commit();
 
            // update selected item and title, then close the drawer
            mDrawerList.setItemChecked(position, true);
            mDrawerList.setSelection(position);
            setTitle(navMenuTitles[position]);
            mDrawerLayout.closeDrawer(mDrawerList);
        } else {
            // error in creating fragment
            Log.e("MainActivity", "Error in creating fragment");
        }
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main_slider, menu);
		return true;
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item){
		// tiggke bav drawer on selecting cation bar app icon / title
		if(mDrawerToggle.onOptionsItemSelected(item)){
			return true;
		}
		// handle action bar actions click
		switch(item.getItemId()){
		case R.id.action_settings:
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}
	
	/**
	 * call when invalidateOptionsMenu() is triggered
	 */
	@Override
	public boolean onPrepareOptionsMenu(Menu menu){
		// if nav drawer is opened, hide the action items
		boolean drawerOpen = mDrawerLayout.isDrawerOpen(mDrawerList);
		menu.findItem(R.id.action_settings).setVisible(!drawerOpen);
		return super.onPrepareOptionsMenu(menu);
	}
	
	@Override
	public void setTitle(CharSequence title){
		mTitle = title;
		getActionBar().setTitle(mTitle);
	}
	
	/**
	 * when using the actionbardrawertoggle, it must be called
	 * during onPostCreate() and on ConfigurationChanged()
	 */
	@Override
	protected void onPostCreate(Bundle savedInstanceState){
		super.onPostCreate(savedInstanceState);
		// synchronise the toggle state after onRestoreInstancestate has happened
		mDrawerToggle.syncState();
	}
	
	@Override
	public void onConfigurationChanged(Configuration newConfig){
		super.onConfigurationChanged(newConfig);
		// pass any configuration changes to drawer toggles
		mDrawerToggle.onConfigurationChanged(newConfig);
	}
}
